mod analyzer;
mod manifest;
mod router;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use memchr::memmem;
use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use monoio::net::{ListenerOpts, TcpListener, TcpStream};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::{c_char, CString};
use std::hash::{Hash, Hasher};
use std::net::{SocketAddr, ToSocketAddrs};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use url::form_urlencoded;

use crate::analyzer::{
    DynamicFastPathResponse, DynamicValueSourceKind, JsonTemplateKind, JsonValueTemplate,
    TextSegment,
};
use crate::manifest::{HttpServerConfigInput, ManifestInput};
use crate::router::{ExactStaticRoute, MatchedRoute, Router};

// ─── Constants ────────────────────────────────────────────────────────────────
// Gotta add support for these to be changed.

const FALLBACK_DEFAULT_HOST: &str = "127.0.0.1";
const FALLBACK_DEFAULT_BACKLOG: i32 = 2048;
const FALLBACK_MAX_HEADER_BYTES: usize = 16 * 1024;
const FALLBACK_HOT_GET_ROOT_HTTP11: &str = "GET / HTTP/1.1\r\n";
const FALLBACK_HOT_GET_ROOT_HTTP10: &str = "GET / HTTP/1.0\r\n";
const FALLBACK_HEADER_CONNECTION_PREFIX: &str = "connection:";
const FALLBACK_HEADER_CONTENT_LENGTH_PREFIX: &str = "content-length:";
const FALLBACK_HEADER_TRANSFER_ENCODING_PREFIX: &str = "transfer-encoding:";
const BRIDGE_VERSION: u8 = 1;
const REQUEST_FLAG_QUERY_PRESENT: u16 = 1 << 0;
const REQUEST_FLAG_BODY_PRESENT: u16 = 1 << 1;
/// Sentinel handler ID dispatched to JS when no route matches — JS treats this as 404.
const NOT_FOUND_HANDLER_ID: u32 = 0;
// Pre-built 404 responses — zero allocation per request
const NOT_FOUND_RESPONSE_KEEP_ALIVE: &[u8] = b"HTTP/1.1 404 Not Found\r\ncontent-length: 27\r\nconnection: keep-alive\r\ncontent-type: application/json; charset=utf-8\r\n\r\n{\"error\":\"Route not found\"}";
const NOT_FOUND_RESPONSE_CLOSE: &[u8] = b"HTTP/1.1 404 Not Found\r\ncontent-length: 27\r\nconnection: close\r\ncontent-type: application/json; charset=utf-8\r\n\r\n{\"error\":\"Route not found\"}";

/// Security: Maximum number of headers we allow per request
const MAX_HEADER_COUNT: usize = 64;
/// Security: Maximum URL length to prevent abuse
const MAX_URL_LENGTH: usize = 8192;
/// Security: Maximum single header value length
const MAX_HEADER_VALUE_LENGTH: usize = 8192;
/// Security: Maximum request body size (1 MB)
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Buffer pool: initial capacity for connection read buffers
const BUFFER_INITIAL_CAPACITY: usize = 8192;
/// Buffer pool: max buffers held per thread
const BUFFER_POOL_MAX_SIZE: usize = 256;
/// Buffer pool: max buffer size to recycle (don't recycle oversized buffers)
const BUFFER_POOL_MAX_RECYCLE_SIZE: usize = 65536;
const DEFAULT_DISPATCH_QUEUE_CAPACITY: usize = 8192;
const DEFAULT_DISPATCH_TIMEOUT_MS: u64 = 3000;
const DEFAULT_DISPATCH_BATCH_MAX_ITEMS: u32 = 256;
const DEFAULT_DISPATCH_BATCH_MAX_BYTES: usize = 1024 * 1024;
const DEFAULT_CACHE_MAX_ENTRIES: usize = 4096;
const DEFAULT_CACHE_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_CACHE_MAX_VALUE_BYTES: usize = 128 * 1024;
const DEFAULT_CACHE_PROMOTE_HITS: u32 = 16;

type Buffer = Vec<u8>;
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

#[derive(Default)]
struct DispatchMetrics {
    queue_depth_peak: u64,
    queue_full_drops: u64,
    dispatch_timeouts: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_promotions: u64,
    dispatch_wait_ns_total: u64,
    dispatch_wait_samples: u64,
}

struct DispatchCacheEntry {
    stable_hits: u32,
    last_response_hash: u64,
    cached: Option<Vec<u8>>,
    last_touch: u64,
}

struct DispatchQueuedRequest {
    request_id: u64,
    payload: Buffer,
}

struct DispatchBridgeState {
    queue: VecDeque<DispatchQueuedRequest>,
    pending: HashMap<u64, mpsc::SyncSender<Buffer>>,
    batch_allocs: HashMap<usize, usize>,
    cache: HashMap<Vec<u8>, DispatchCacheEntry>,
    cache_total_bytes: usize,
    touch_counter: u64,
    metrics: DispatchMetrics,
}

struct DispatchBridgeConfig {
    queue_capacity: usize,
    dispatch_timeout: Duration,
    batch_max_items: u32,
    batch_max_bytes: usize,
    cache_max_entries: usize,
    cache_max_total_bytes: usize,
    cache_max_value_bytes: usize,
    cache_promote_hits: u32,
    debug: bool,
}

struct DispatchBridge {
    next_request_id: AtomicU64,
    cache_candidate_handlers: HashSet<u32>,
    config: DispatchBridgeConfig,
    state: Mutex<DispatchBridgeState>,
}

impl DispatchBridge {
    fn from_env(cache_candidate_handlers: HashSet<u32>) -> Self {
        let config = DispatchBridgeConfig {
            queue_capacity: read_env_usize(
                "HTTP_NATIVE_DISPATCH_QUEUE_CAPACITY",
                DEFAULT_DISPATCH_QUEUE_CAPACITY,
                1,
                1_000_000,
            ),
            dispatch_timeout: Duration::from_millis(read_env_u64(
                "HTTP_NATIVE_DISPATCH_TIMEOUT_MS",
                DEFAULT_DISPATCH_TIMEOUT_MS,
                1,
                60_000,
            )),
            batch_max_items: read_env_u32(
                "HTTP_NATIVE_DISPATCH_BATCH_MAX_ITEMS",
                DEFAULT_DISPATCH_BATCH_MAX_ITEMS,
                1,
                4_096,
            ),
            batch_max_bytes: read_env_usize(
                "HTTP_NATIVE_DISPATCH_BATCH_MAX_BYTES",
                DEFAULT_DISPATCH_BATCH_MAX_BYTES,
                4 * 1024,
                16 * 1024 * 1024,
            ),
            cache_max_entries: read_env_usize(
                "HTTP_NATIVE_CACHE_MAX_ENTRIES",
                DEFAULT_CACHE_MAX_ENTRIES,
                0,
                1_000_000,
            ),
            cache_max_total_bytes: read_env_usize(
                "HTTP_NATIVE_CACHE_MAX_TOTAL_BYTES",
                DEFAULT_CACHE_MAX_TOTAL_BYTES,
                0,
                2 * 1024 * 1024 * 1024,
            ),
            cache_max_value_bytes: read_env_usize(
                "HTTP_NATIVE_CACHE_MAX_VALUE_BYTES",
                DEFAULT_CACHE_MAX_VALUE_BYTES,
                0,
                4 * 1024 * 1024,
            ),
            cache_promote_hits: read_env_u32(
                "HTTP_NATIVE_CACHE_PROMOTE_HITS",
                DEFAULT_CACHE_PROMOTE_HITS,
                1,
                10_000,
            ),
            debug: read_env_bool("HTTP_NATIVE_BRIDGE_DEBUG"),
        };

        Self {
            next_request_id: AtomicU64::new(1),
            cache_candidate_handlers,
            config,
            state: Mutex::new(DispatchBridgeState {
                queue: VecDeque::new(),
                pending: HashMap::new(),
                batch_allocs: HashMap::new(),
                cache: HashMap::new(),
                cache_total_bytes: 0,
                touch_counter: 0,
                metrics: DispatchMetrics::default(),
            }),
        }
    }

    fn dispatch(&self, request: Buffer) -> Result<Buffer> {
        let handler_id = extract_handler_id(request.as_slice()).unwrap_or_default();
        let cache_eligible = self.cache_candidate_handlers.contains(&handler_id);
        let cache_key = if cache_eligible {
            Some(request.clone())
        } else {
            None
        };
        if cache_eligible {
            if let Some(hit) = self.try_cache_hit(request.as_slice()) {
                return Ok(hit);
            }
        }

        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (response_tx, response_rx) = mpsc::sync_channel::<Buffer>(1);

        {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            if state.queue.len() >= self.config.queue_capacity {
                state.metrics.queue_full_drops = state.metrics.queue_full_drops.saturating_add(1);
                if self.config.debug {
                    eprintln!("[http-native][bridge] queue full");
                }
                return Err(anyhow!("dispatch queue full"));
            }
            state.pending.insert(request_id, response_tx);
            state.queue.push_back(DispatchQueuedRequest {
                request_id,
                payload: request,
            });
            let depth = state.queue.len() as u64;
            if depth > state.metrics.queue_depth_peak {
                state.metrics.queue_depth_peak = depth;
            }
        }

        let wait_started = Instant::now();
        let response = match response_rx.recv_timeout(self.config.dispatch_timeout) {
            Ok(value) => value,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
                state.pending.remove(&request_id);
                state.metrics.dispatch_timeouts = state.metrics.dispatch_timeouts.saturating_add(1);
                if self.config.debug {
                    eprintln!("[http-native][bridge] dispatch timeout for request_id={request_id}");
                }
                return Err(anyhow!("dispatch timed out"));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
                state.pending.remove(&request_id);
                return Err(anyhow!("dispatch channel disconnected"));
            }
        };

        let wait_ns = wait_started.elapsed().as_nanos() as u64;
        {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            state.metrics.dispatch_wait_ns_total =
                state.metrics.dispatch_wait_ns_total.saturating_add(wait_ns);
            state.metrics.dispatch_wait_samples =
                state.metrics.dispatch_wait_samples.saturating_add(1);
        }

        if let Some(cache_key) = cache_key.as_ref() {
            self.observe_cache(cache_key.as_slice(), response.as_slice());
        }

        Ok(response)
    }

    fn poll_dispatch_batch(&self, requested_max_items: u32) -> Result<*mut u8> {
        let max_items = if requested_max_items == 0 {
            self.config.batch_max_items
        } else {
            requested_max_items.min(self.config.batch_max_items)
        };
        if max_items == 0 {
            return Ok(ptr::null_mut());
        }

        let mut batch_items: Vec<DispatchQueuedRequest> = Vec::new();
        let mut payload_bytes = 4usize; // item_count
        {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            if state.queue.is_empty() {
                return Ok(ptr::null_mut());
            }

            while (batch_items.len() as u32) < max_items {
                let Some(next) = state.queue.front() else {
                    break;
                };
                let item_size = 12usize
                    .checked_add(next.payload.len())
                    .ok_or_else(|| anyhow!("dispatch batch item size overflow"))?;
                if !batch_items.is_empty()
                    && payload_bytes
                        .checked_add(item_size)
                        .ok_or_else(|| anyhow!("dispatch batch size overflow"))?
                        > self.config.batch_max_bytes
                {
                    break;
                }

                payload_bytes = payload_bytes
                    .checked_add(item_size)
                    .ok_or_else(|| anyhow!("dispatch batch size overflow"))?;
                let item = state
                    .queue
                    .pop_front()
                    .ok_or_else(|| anyhow!("dispatch queue underflow"))?;
                batch_items.push(item);
            }
        }

        if batch_items.is_empty() {
            return Ok(ptr::null_mut());
        }

        let mut frame = Vec::with_capacity(
            payload_bytes
                .checked_add(4)
                .ok_or_else(|| anyhow!("dispatch frame size overflow"))?,
        );
        push_u32(&mut frame, payload_bytes as u32);
        push_u32(&mut frame, batch_items.len() as u32);
        for item in batch_items {
            frame.extend_from_slice(&item.request_id.to_le_bytes());
            push_u32(&mut frame, item.payload.len() as u32);
            frame.extend_from_slice(item.payload.as_slice());
        }
        frame.shrink_to_fit();

        let ptr = frame.as_mut_ptr();
        let len = frame.len();
        {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            state.batch_allocs.insert(ptr as usize, len);
        }
        std::mem::forget(frame);
        Ok(ptr)
    }

    fn free_dispatch_batch(&self, batch_ptr: *mut u8) {
        if batch_ptr.is_null() {
            return;
        }

        let len = {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            state.batch_allocs.remove(&(batch_ptr as usize))
        };
        if let Some(len) = len {
            unsafe {
                drop(Vec::from_raw_parts(batch_ptr, len, len));
            }
        }
    }

    fn submit_response(&self, request_id: u64, response: Buffer) -> bool {
        let sender = {
            let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
            state.pending.remove(&request_id)
        };
        let Some(sender) = sender else {
            return false;
        };
        sender.send(response).is_ok()
    }

    fn try_cache_hit(&self, cache_key: &[u8]) -> Option<Buffer> {
        let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
        state.touch_counter = state.touch_counter.wrapping_add(1);
        let touch = state.touch_counter;
        let mut hit = None;
        if let Some(entry) = state.cache.get_mut(cache_key) {
            entry.last_touch = touch;
            if let Some(value) = entry.cached.as_ref() {
                hit = Some(value.clone());
            }
        }

        if hit.is_some() {
            state.metrics.cache_hits = state.metrics.cache_hits.saturating_add(1);
        } else {
            state.metrics.cache_misses = state.metrics.cache_misses.saturating_add(1);
        }
        hit
    }

    fn observe_cache(&self, cache_key: &[u8], response: &[u8]) {
        if self.config.cache_max_entries == 0
            || self.config.cache_max_total_bytes == 0
            || self.config.cache_max_value_bytes == 0
        {
            return;
        }

        let response_hash = hash_bytes(response);
        let mut state = self.state.lock().expect("dispatch bridge mutex poisoned");
        state.touch_counter = state.touch_counter.wrapping_add(1);
        let touch = state.touch_counter;

        let mut promoted = false;
        let mut promote_len = 0usize;
        let mut removed_prev_len = 0usize;

        if let Some(entry) = state.cache.get_mut(cache_key) {
            entry.last_touch = touch;
            if entry.last_response_hash == response_hash {
                entry.stable_hits = entry.stable_hits.saturating_add(1);
            } else {
                entry.stable_hits = 1;
                entry.last_response_hash = response_hash;
                if let Some(prev) = entry.cached.take() {
                    removed_prev_len = prev.len();
                }
            }

            if entry.cached.is_none()
                && entry.stable_hits >= self.config.cache_promote_hits
                && response.len() <= self.config.cache_max_value_bytes
            {
                entry.cached = Some(response.to_vec());
                promoted = true;
                promote_len = response.len();
            }
        } else {
            state.cache.insert(
                cache_key.to_vec(),
                DispatchCacheEntry {
                    stable_hits: 1,
                    last_response_hash: response_hash,
                    cached: None,
                    last_touch: touch,
                },
            );
        }

        if removed_prev_len > 0 {
            state.cache_total_bytes = state.cache_total_bytes.saturating_sub(removed_prev_len);
        }
        if promoted {
            state.cache_total_bytes = state.cache_total_bytes.saturating_add(promote_len);
            state.metrics.cache_promotions = state.metrics.cache_promotions.saturating_add(1);
        }

        evict_dispatch_cache(&mut state, &self.config);
    }

    fn debug_snapshot(&self) -> Option<String> {
        if !self.config.debug {
            return None;
        }
        let state = self.state.lock().expect("dispatch bridge mutex poisoned");
        let avg_wait_ms = if state.metrics.dispatch_wait_samples == 0 {
            0.0
        } else {
            (state.metrics.dispatch_wait_ns_total as f64
                / state.metrics.dispatch_wait_samples as f64)
                / 1_000_000.0
        };
        Some(format!(
            "queue_depth={} queue_depth_peak={} queue_full={} timeouts={} cache_hit={} cache_miss={} cache_promotions={} avg_wait_ms={avg_wait_ms:.3}",
            state.queue.len(),
            state.metrics.queue_depth_peak,
            state.metrics.queue_full_drops,
            state.metrics.dispatch_timeouts,
            state.metrics.cache_hits,
            state.metrics.cache_misses,
            state.metrics.cache_promotions,
        ))
    }
}

fn evict_dispatch_cache(state: &mut DispatchBridgeState, config: &DispatchBridgeConfig) {
    while state.cache.len() > config.cache_max_entries
        || state.cache_total_bytes > config.cache_max_total_bytes
    {
        let Some(evict_key) = state
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_touch)
            .map(|(key, _)| key.clone())
        else {
            break;
        };

        if let Some(entry) = state.cache.remove(evict_key.as_slice()) {
            if let Some(value) = entry.cached {
                state.cache_total_bytes = state.cache_total_bytes.saturating_sub(value.len());
            }
        }
    }
}

fn extract_handler_id(request: &[u8]) -> Option<u32> {
    if request.len() < 8 {
        return None;
    }
    Some(u32::from_le_bytes([
        request[4], request[5], request[6], request[7],
    ]))
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn read_env_usize(name: &str, fallback: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(fallback)
}

fn read_env_u64(name: &str, fallback: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(fallback)
}

fn read_env_u32(name: &str, fallback: u32, min: u32, max: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(fallback)
}

fn read_env_bool(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

// ─── Thread-Local Buffer Pool ─────────────────────────────────────────────────
//
// Eliminates per-connection Vec<u8> allocations by recycling buffers.

thread_local! {
    static BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(BUFFER_POOL_MAX_SIZE));
}

fn acquire_buffer() -> Vec<u8> {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(BUFFER_INITIAL_CAPACITY))
    })
}

fn release_buffer(mut buf: Vec<u8>) {
    if buf.capacity() > BUFFER_POOL_MAX_RECYCLE_SIZE {
        return; // Don't recycle oversized buffers
    }
    buf.clear();
    BUFFER_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < BUFFER_POOL_MAX_SIZE {
            pool.push(buf);
        }
    });
}

// ─── Server Configuration ─────────────────────────────────────────────────────

#[derive(Clone)]
struct HttpServerConfig {
    default_host: String,
    default_backlog: i32,
    max_header_bytes: usize,
    hot_get_root_http11: Vec<u8>,
    hot_get_root_http10: Vec<u8>,
    header_connection_prefix: Vec<u8>,
    header_content_length_prefix: Vec<u8>,
    header_transfer_encoding_prefix: Vec<u8>,
}

impl HttpServerConfig {
    fn from_manifest(manifest: &ManifestInput) -> Result<Self> {
        let input = manifest.server_config.as_ref();
        let default_backlog = input
            .and_then(|config| config.default_backlog)
            .unwrap_or(FALLBACK_DEFAULT_BACKLOG);
        let max_header_bytes = input
            .and_then(|config| config.max_header_bytes)
            .unwrap_or(FALLBACK_MAX_HEADER_BYTES);

        if default_backlog <= 0 {
            return Err(anyhow!(
                "serverConfig.defaultBacklog must be greater than 0"
            ));
        }

        if max_header_bytes == 0 {
            return Err(anyhow!(
                "serverConfig.maxHeaderBytes must be greater than 0"
            ));
        }

        Ok(Self {
            default_host: config_string(
                input,
                |config| config.default_host.as_deref(),
                FALLBACK_DEFAULT_HOST,
            ),
            default_backlog,
            max_header_bytes,
            hot_get_root_http11: config_string(
                input,
                |config| config.hot_get_root_http11.as_deref(),
                FALLBACK_HOT_GET_ROOT_HTTP11,
            )
            .into_bytes(),
            hot_get_root_http10: config_string(
                input,
                |config| config.hot_get_root_http10.as_deref(),
                FALLBACK_HOT_GET_ROOT_HTTP10,
            )
            .into_bytes(),
            header_connection_prefix: config_string(
                input,
                |config| config.header_connection_prefix.as_deref(),
                FALLBACK_HEADER_CONNECTION_PREFIX,
            )
            .into_bytes(),
            header_content_length_prefix: config_string(
                input,
                |config| config.header_content_length_prefix.as_deref(),
                FALLBACK_HEADER_CONTENT_LENGTH_PREFIX,
            )
            .into_bytes(),
            header_transfer_encoding_prefix: config_string(
                input,
                |config| config.header_transfer_encoding_prefix.as_deref(),
                FALLBACK_HEADER_TRANSFER_ENCODING_PREFIX,
            )
            .into_bytes(),
        })
    }
}

// ─── FFI Interface ────────────────────────────────────────────────────────────

pub struct NativeListenOptions {
    pub host: Option<String>,
    pub port: u16,
    pub backlog: Option<i32>,
}

struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    wake_addrs: Vec<SocketAddr>,
}

pub struct NativeServerHandle {
    host: String,
    port: u32,
    url: String,
    bridge: Arc<DispatchBridge>,
    shutdown: Mutex<Option<ShutdownHandle>>,
    closed: Mutex<Option<Vec<mpsc::Receiver<()>>>>,
}

impl NativeServerHandle {
    pub fn host(&self) -> String {
        self.host.clone()
    }

    pub fn port(&self) -> u32 {
        self.port
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn close(&self) -> Result<()> {
        if let Some(shutdown) = self
            .shutdown
            .lock()
            .expect("shutdown mutex poisoned")
            .take()
        {
            shutdown.flag.store(true, Ordering::SeqCst);
            wake_workers(shutdown.wake_addrs.as_slice(), 8);
        }

        if let Some(receivers) = self.closed.lock().expect("closed mutex poisoned").take() {
            for receiver in receivers {
                let _ = receiver.recv();
            }
        }

        Ok(())
    }
}

fn start_server_internal(
    manifest_json: &str,
    options: NativeListenOptions,
) -> Result<NativeServerHandle> {
    let manifest: ManifestInput = serde_json::from_str(manifest_json)?;
    validate_manifest(&manifest)?;
    let cache_candidate_handlers = manifest
        .routes
        .iter()
        .filter(|route| route.js_dispatch && route.cache_candidate)
        .map(|route| route.handler_id)
        .collect::<HashSet<_>>();
    let bridge = Arc::new(DispatchBridge::from_env(cache_candidate_handlers));
    let dispatcher = Arc::new(JsDispatcher {
        bridge: Arc::clone(&bridge),
    });
    if let Some(snapshot) = bridge.debug_snapshot() {
        eprintln!("[http-native][bridge] {snapshot}");
    }
    let server_config = Arc::new(HttpServerConfig::from_manifest(&manifest)?);
    let router = Arc::new(Router::from_manifest(&manifest)?);

    let worker_count = worker_count_for(&options);
    let (startup_tx, startup_rx) = mpsc::sync_channel::<Result<SocketAddr, String>>(worker_count);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let mut closed_receivers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let (closed_tx, closed_rx) = mpsc::channel::<()>();
        closed_receivers.push(closed_rx);

        let thread_router = Arc::clone(&router);
        let thread_dispatcher = Arc::clone(&dispatcher);
        let thread_config = Arc::clone(&server_config);
        let thread_shutdown = Arc::clone(&shutdown_flag);
        let thread_options = NativeListenOptions {
            host: options.host.clone(),
            port: options.port,
            backlog: options.backlog,
        };
        let thread_startup_tx = startup_tx.clone();

        std::thread::spawn(move || {
            let startup_tx_error = thread_startup_tx.clone();
            let result = (|| -> Result<()> {
                let mut runtime = monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
                    .build()
                    .context("failed to build monoio runtime")?;

                runtime.block_on(async move {
                    let listener = bind_listener(&thread_options, thread_config.as_ref())
                        .context("failed to create monoio listener")?;
                    let local_addr = listener.local_addr()?;
                    let _ = thread_startup_tx.send(Ok(local_addr));
                    run_server(
                        listener,
                        thread_router,
                        thread_dispatcher,
                        thread_config,
                        thread_shutdown,
                    )
                    .await
                })
            })();

            if let Err(error) = &result {
                let _ = startup_tx_error.send(Err(error.to_string()));
                eprintln!("[http-native] native server error: {error:#}");
            }

            let _ = closed_tx.send(());
        });
    }

    let mut wake_addrs = Vec::with_capacity(worker_count);
    let mut local_addr = None;
    for _ in 0..worker_count {
        match startup_rx.recv() {
            Ok(Ok(addr)) => {
                if local_addr.is_none() {
                    local_addr = Some(addr);
                }
                wake_addrs.push(addr);
            }
            Ok(Err(message)) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                wake_workers(wake_addrs.as_slice(), 4);
                for receiver in closed_receivers {
                    let _ = receiver.recv();
                }
                return Err(anyhow!(message));
            }
            Err(_) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                wake_workers(wake_addrs.as_slice(), 4);
                for receiver in closed_receivers {
                    let _ = receiver.recv();
                }
                return Err(anyhow!("Native server exited before reporting readiness"));
            }
        }
    }

    let local_addr = local_addr.expect("worker count must be at least 1");

    let host = local_addr.ip().to_string();
    let port = local_addr.port() as u32;

    Ok(NativeServerHandle {
        host: host.clone(),
        port,
        url: format!("http://{host}:{port}"),
        bridge,
        shutdown: Mutex::new(Some(ShutdownHandle {
            flag: shutdown_flag,
            wake_addrs,
        })),
        closed: Mutex::new(Some(closed_receivers)),
    })
}

#[no_mangle]
pub unsafe extern "C" fn http_native_start_server(
    manifest_json_ptr: *const u8,
    manifest_json_len: usize,
    host_ptr: *const u8,
    host_len: usize,
    port: u16,
    backlog: i32,
) -> *mut NativeServerHandle {
    let start_result = (|| -> Result<NativeServerHandle> {
        let manifest_json = read_required_utf8(manifest_json_ptr, manifest_json_len, "manifest_json")?;
        let host = read_optional_utf8(host_ptr, host_len, "host")?;
        let options = NativeListenOptions {
            host,
            port,
            backlog: (backlog > 0).then_some(backlog),
        };

        start_server_internal(manifest_json.as_str(), options)
    })();

    match start_result {
        Ok(handle) => {
            clear_last_error();
            Box::into_raw(Box::new(handle))
        }
        Err(error) => {
            set_last_error(error.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_poll_dispatch_batch(
    handle: *mut NativeServerHandle,
    max_items: u32,
) -> *mut u8 {
    if handle.is_null() {
        set_last_error("server handle was null");
        return ptr::null_mut();
    }

    let handle_ref = &*handle;
    match handle_ref.bridge.poll_dispatch_batch(max_items) {
        Ok(ptr) => {
            clear_last_error();
            ptr
        }
        Err(error) => {
            set_last_error(error.to_string());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_dispatch_batch_free(
    handle: *mut NativeServerHandle,
    batch_ptr: *mut u8,
) {
    if handle.is_null() {
        if !batch_ptr.is_null() {
            set_last_error("server handle was null");
        }
        return;
    }

    let handle_ref = &*handle;
    handle_ref.bridge.free_dispatch_batch(batch_ptr);
}

#[no_mangle]
pub unsafe extern "C" fn http_native_submit_dispatch_response(
    handle: *mut NativeServerHandle,
    request_id: u64,
    response_ptr: *const u8,
    response_len: usize,
) -> bool {
    if handle.is_null() {
        set_last_error("server handle was null");
        return false;
    }
    if response_ptr.is_null() && response_len > 0 {
        set_last_error("response pointer was null");
        return false;
    }

    let response = if response_len == 0 {
        Buffer::new()
    } else {
        slice::from_raw_parts(response_ptr, response_len).to_vec()
    };
    let handle_ref = &*handle;
    let submitted = handle_ref.bridge.submit_response(request_id, response);
    if !submitted {
        set_last_error("request id not pending");
        return false;
    }

    clear_last_error();
    true
}

#[no_mangle]
pub extern "C" fn http_native_take_last_error() -> *mut c_char {
    let mut slot = LAST_ERROR.lock().expect("last error mutex poisoned");
    match slot.take() {
        Some(message) => message.into_raw(),
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_string_free(value: *mut c_char) {
    if !value.is_null() {
        let _ = CString::from_raw(value);
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_server_snapshot_json(
    handle: *const NativeServerHandle,
) -> *mut c_char {
    if handle.is_null() {
        set_last_error("server handle was null");
        return ptr::null_mut();
    }

    let handle_ref = &*handle;
    let snapshot = serde_json::json!({
        "host": handle_ref.host(),
        "port": handle_ref.port(),
        "url": handle_ref.url(),
    })
    .to_string();

    match CString::new(snapshot) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            set_last_error("failed to encode server snapshot");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_server_close(handle: *mut NativeServerHandle) -> bool {
    if handle.is_null() {
        set_last_error("server handle was null");
        return false;
    }

    match (&*handle).close() {
        Ok(()) => {
            clear_last_error();
            true
        }
        Err(error) => {
            set_last_error(error.to_string());
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn http_native_server_free(handle: *mut NativeServerHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

fn worker_count_for(options: &NativeListenOptions) -> usize {
    if options.port == 0 {
        return 1;
    }

    std::env::var("HTTP_NATIVE_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|parallelism| {
                    parallelism
                        .get()
                        .saturating_mul(4)
                        .clamp(4, 64)
                })
                .unwrap_or(1)
        })
}

fn wake_workers(addrs: &[SocketAddr], attempts_per_worker: usize) {
    if addrs.is_empty() {
        return;
    }

    let repeats = attempts_per_worker.max(1);
    let attempts = addrs.len().saturating_mul(repeats);
    for attempt in 0..attempts {
        let addr = addrs[attempt % addrs.len()];
        let _ = std::net::TcpStream::connect(addr);
    }
}

// ─── JS Dispatcher ────────────────────────────────────────────────────────────

struct JsDispatcher {
    bridge: Arc<DispatchBridge>,
}

impl JsDispatcher {
    fn dispatch(&self, request: Buffer) -> Result<Buffer> {
        self.bridge.dispatch(request)
    }
}

// ─── Server Loop ──────────────────────────────────────────────────────────────

async fn run_server(
    listener: TcpListener,
    router: Arc<Router>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<()> {
    loop {
        if shutdown_flag.load(Ordering::Acquire) {
            break;
        }

        match listener.accept().await {
            Ok((stream, _)) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                if let Err(error) = stream.set_nodelay(true) {
                    eprintln!("[http-native] failed to enable TCP_NODELAY: {error}");
                }

                let router = Arc::clone(&router);
                let dispatcher = Arc::clone(&dispatcher);
                let server_config = Arc::clone(&server_config);

                monoio::spawn(async move {
                    if let Err(error) =
                        handle_connection(stream, router, dispatcher, server_config).await
                    {
                        eprintln!("[http-native] connection error: {error}");
                    }
                });
            }
            Err(error) => {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }

                eprintln!("[http-native] accept error: {error}");
            }
        }
    }

    Ok(())
}

// ─── Parsed Request (from httparse) ───────────────────────────────────────────

struct ParsedRequest<'a> {
    method: &'a [u8],
    target: &'a [u8],
    path: &'a [u8],
    keep_alive: bool,
    header_bytes: usize,
    has_body: bool,
    content_length: Option<usize>,
    /// Pre-parsed header pairs — stored once, used by both routing and bridge
    headers: Vec<(&'a str, &'a str)>,
}

// ─── Connection Handler with Buffer Pool ──────────────────────────────────────

async fn handle_connection(
    mut stream: TcpStream,
    router: Arc<Router>,
    dispatcher: Arc<JsDispatcher>,
    server_config: Arc<HttpServerConfig>,
) -> Result<()> {
    let mut buffer = acquire_buffer();

    let result = handle_connection_inner(
        &mut stream,
        &mut buffer,
        &router,
        &dispatcher,
        &server_config,
    )
    .await;

    release_buffer(buffer);
    result
}

async fn handle_connection_inner(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    router: &Router,
    dispatcher: &JsDispatcher,
    server_config: &HttpServerConfig,
) -> Result<()> {
    loop {
        // Try hot-path parsing first (GET / with known prefix)
        let parsed = loop {
            let result = if router.exact_get_root().is_some() {
                parse_hot_root_request(buffer, server_config)
                    .or_else(|| parse_request_httparse(buffer))
            } else {
                parse_request_httparse(buffer)
            };

            if let Some(parsed) = result {
                break parsed;
            }

            if find_header_end(buffer).is_some() {
                // Headers complete but couldn't parse — malformed request
                stream.shutdown().await?;
                return Ok(());
            }

            // SAFETY: We take ownership of the buffer, read into it, then put it back
            let owned_buf = std::mem::take(buffer);
            let (read_result, next_buffer) = stream.read(owned_buf).await;
            *buffer = next_buffer;
            let bytes_read = read_result?;

            if bytes_read == 0 {
                return Ok(());
            }

            if buffer.len() > server_config.max_header_bytes {
                // Security: Request header too large
                let response = build_error_response_bytes(
                    431,
                    b"{\"error\":\"Request Header Fields Too Large\"}",
                    false,
                );
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
                stream.shutdown().await?;
                return Ok(());
            }
        };

        let header_bytes = parsed.header_bytes;
        let keep_alive = parsed.keep_alive;
        let has_body = parsed.has_body;
        let content_length = parsed.content_length;

        // ── Fast path: static routes (zero-copy from borrowed parse data) ──
        if !has_body && parsed.method == b"GET" {
            if parsed.path == b"/" {
                if let Some(static_route) = router.exact_get_root() {
                    drop(parsed);
                    drain_consumed_bytes(buffer, header_bytes);
                    write_exact_static_response(stream, static_route, keep_alive).await?;
                    if !keep_alive {
                        stream.shutdown().await?;
                        return Ok(());
                    }
                    continue;
                }
            }
            if let Some(static_route) = router.exact_static_route(parsed.method, parsed.path) {
                drop(parsed);
                drain_consumed_bytes(buffer, header_bytes);
                write_exact_static_response(stream, static_route, keep_alive).await?;
                if !keep_alive {
                    stream.shutdown().await?;
                    return Ok(());
                }
                continue;
            }
        }

        // ── Zero-copy path: non-body requests ──
        // Build dispatch envelope directly from borrowed parse data, avoiding
        // String/Vec allocations for method, target, path, and headers.
        if !has_body {
            let dispatch_decision = build_dispatch_decision_zero_copy(router, &parsed, &[])?;
            drop(parsed);
            drain_consumed_bytes(buffer, header_bytes);

            match dispatch_decision {
                DispatchDecision::BridgeRequest(request) => {
                    write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive)
                        .await?;
                }
                DispatchDecision::SpecializedResponse(response) => {
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                }
                DispatchDecision::NotFound => {
                    write_not_found_response(stream, keep_alive).await?;
                }
            }

            if !keep_alive {
                stream.shutdown().await?;
                return Ok(());
            }
            continue;
        }

        // ── Body requests: need owned copies to release buffer for body read ──
        let method_owned: Vec<u8> = parsed.method.to_vec();
        let target_owned: Vec<u8> = parsed.target.to_vec();
        let path_owned: Vec<u8> = parsed.path.to_vec();
        let headers_owned: Vec<(String, String)> = parsed
            .headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        drop(parsed);

        // ── Read request body ──────────────────────────────────────
        let body_bytes: Vec<u8> = {
            let content_length = match content_length {
                Some(len) => len,
                None => {
                    let response =
                        build_error_response_bytes(411, b"{\"error\":\"Length Required\"}", false);
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            };

            if content_length > MAX_BODY_BYTES {
                let response =
                    build_error_response_bytes(413, b"{\"error\":\"Payload Too Large\"}", false);
                let (write_result, _) = stream.write_all(response).await;
                write_result?;
                stream.shutdown().await?;
                return Ok(());
            }

            let already_in_buffer = if buffer.len() > header_bytes {
                buffer.len() - header_bytes
            } else {
                0
            };

            if already_in_buffer >= content_length {
                let body = buffer[header_bytes..header_bytes + content_length].to_vec();
                drain_consumed_bytes(buffer, header_bytes + content_length);
                body
            } else {
                let mut body = Vec::with_capacity(content_length);
                if already_in_buffer > 0 {
                    body.extend_from_slice(&buffer[header_bytes..]);
                }
                drain_consumed_bytes(buffer, buffer.len());

                while body.len() < content_length {
                    let remaining = content_length - body.len();
                    let chunk_buf = vec![0u8; remaining.min(65536)];
                    let (read_result, returned_buf) = stream.read(chunk_buf).await;
                    let bytes_read = read_result?;
                    if bytes_read == 0 {
                        return Ok(());
                    }
                    body.extend_from_slice(&returned_buf[..bytes_read]);
                }
                body.truncate(content_length);
                body
            }
        };

        let dispatch_request = build_dispatch_request_owned(
            router,
            &method_owned,
            &target_owned,
            &path_owned,
            &headers_owned,
            &body_bytes,
        )?;

        match dispatch_request {
            Some(request) => {
                write_dynamic_dispatch_response(stream, dispatcher, request, keep_alive).await?;
            }
            None => {
                write_not_found_response(stream, keep_alive).await?;
            }
        }

        if !keep_alive {
            stream.shutdown().await?;
            return Ok(());
        }
    }
}

// ─── httparse-based Request Parsing ───────────────────────────────────────────
//
// Uses the battle-tested `httparse` crate for RFC-compliant zero-copy parsing.
// Single-pass: parses headers once and stores them for reuse by both the
// router and the bridge envelope builder.

fn parse_request_httparse(bytes: &[u8]) -> Option<ParsedRequest<'_>> {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT];
    let mut req = httparse::Request::new(&mut raw_headers);

    let header_len = match req.parse(bytes) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return None,
        Err(_) => return None, // Malformed — caller will handle
    };

    let method = req.method?.as_bytes();
    let target = req.path?.as_bytes();
    let version = req.version?;

    // Security: enforce URL length limit
    if target.len() > MAX_URL_LENGTH {
        return None;
    }

    // Extract path (before '?')
    let path = target.split(|b| *b == b'?').next()?;

    let mut keep_alive = version >= 1; // HTTP/1.1+ defaults to keep-alive
    let mut has_body = false;
    let mut content_length: Option<usize> = None;
    let mut headers = Vec::with_capacity(req.headers.len());

    for header in req.headers.iter() {
        if header.name.is_empty() {
            break;
        }

        // Security: enforce header value length
        if header.value.len() > MAX_HEADER_VALUE_LENGTH {
            return None;
        }

        let name = header.name; // httparse gives us &str
        let value = match std::str::from_utf8(header.value) {
            Ok(v) => v,
            Err(_) => continue, // Skip non-UTF-8 headers
        };

        // Connection handling
        if name.eq_ignore_ascii_case("connection") {
            let lower = value.to_ascii_lowercase();
            if lower.contains("close") {
                keep_alive = false;
            }
            if lower.contains("keep-alive") {
                keep_alive = true;
            }
        }

        // Body detection
        if name.eq_ignore_ascii_case("content-length") {
            let trimmed = value.trim();
            if let Ok(len) = trimmed.parse::<usize>() {
                content_length = Some(len);
                if len > 0 {
                    has_body = true;
                }
            }
        }

        if name.eq_ignore_ascii_case("transfer-encoding") {
            let trimmed = value.trim();
            if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("identity") {
                has_body = true;
            }
        }

        headers.push((name, value));
    }

    Some(ParsedRequest {
        method,
        target,
        path,
        keep_alive,
        header_bytes: header_len,
        has_body,
        content_length,
        headers,
    })
}

// ─── Hot Root Path (GET /) ────────────────────────────────────────────────────
//
// Ultra-fast path for the most common benchmark case. Falls back to httparse
// if the request doesn't exactly match the expected prefix.

fn parse_hot_root_request(
    bytes: &[u8],
    server_config: &HttpServerConfig,
) -> Option<ParsedRequest<'static>> {
    let (_, keep_alive) = if bytes.starts_with(server_config.hot_get_root_http11.as_slice()) {
        (server_config.hot_get_root_http11.len(), true)
    } else if bytes.starts_with(server_config.hot_get_root_http10.as_slice()) {
        (server_config.hot_get_root_http10.len(), false)
    } else {
        return None;
    };

    let header_end = find_header_end(bytes)?;
    let mut keep_alive = keep_alive;
    let mut has_body = false;
    let mut line_start = bytes.iter().position(|b| *b == b'\n')? + 1;

    while line_start + 2 <= header_end {
        let next_end = memmem::find(&bytes[line_start..header_end + 2], b"\r\n")? + line_start;

        if next_end == line_start {
            break;
        }

        let line = &bytes[line_start..next_end];
        if line.len() >= server_config.header_connection_prefix.len()
            && line[..server_config.header_connection_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_connection_prefix.as_slice())
        {
            let value = &line[server_config.header_connection_prefix.len()..];
            if contains_ascii_case_insensitive(value, b"close") {
                keep_alive = false;
            }
            if contains_ascii_case_insensitive(value, b"keep-alive") {
                keep_alive = true;
            }
        } else if line.len() >= server_config.header_content_length_prefix.len()
            && line[..server_config.header_content_length_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_content_length_prefix.as_slice())
        {
            let value =
                trim_ascii_spaces(&line[server_config.header_content_length_prefix.len()..]);
            if value != b"0" {
                has_body = true;
            }
        } else if line.len() >= server_config.header_transfer_encoding_prefix.len()
            && line[..server_config.header_transfer_encoding_prefix.len()]
                .eq_ignore_ascii_case(server_config.header_transfer_encoding_prefix.as_slice())
        {
            let value =
                trim_ascii_spaces(&line[server_config.header_transfer_encoding_prefix.len()..]);
            if !value.is_empty() && !value.eq_ignore_ascii_case(b"identity") {
                has_body = true;
            }
        }

        line_start = next_end + 2;
    }

    Some(ParsedRequest {
        method: b"GET",
        target: b"/",
        path: b"/",
        keep_alive,
        header_bytes: header_end + 4,
        has_body,
        content_length: None,
        headers: Vec::new(), // Hot path: no headers needed for static response
    })
}

// ─── Routing ──────────────────────────────────────────────────────────────────

// ─── Bridge Envelope Building (Single-Pass Headers) ───────────────────────────
//
// Uses the pre-parsed headers from httparse — no second scan of the raw bytes.

/// Zero-copy dispatch: builds the bridge envelope directly from borrowed parse data,
/// avoiding all String/Vec allocations for method, target, path, and headers.
/// Used for non-body requests (GET, DELETE without body, etc.).
enum DispatchDecision {
    BridgeRequest(Buffer),
    SpecializedResponse(Vec<u8>),
    NotFound,
}

fn build_dispatch_decision_zero_copy(
    router: &Router,
    parsed: &ParsedRequest<'_>,
    body: &[u8],
) -> Result<DispatchDecision> {
    let Some(method_code) = method_code_from_bytes(parsed.method) else {
        return Ok(DispatchDecision::NotFound);
    };

    let path_str = match std::str::from_utf8(parsed.path) {
        Ok(s) => s,
        Err(_) => return Ok(DispatchDecision::NotFound),
    };
    let url_str = match std::str::from_utf8(parsed.target) {
        Ok(s) => s,
        Err(_) => return Ok(DispatchDecision::NotFound),
    };

    let normalized_path = normalize_runtime_path(path_str);
    if contains_path_traversal(&normalized_path) {
        return Ok(DispatchDecision::NotFound);
    }

    let Some(matched_route) = router.match_route(method_code, normalized_path.as_ref()) else {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &parsed.headers,
            body,
        )
        .map(DispatchDecision::BridgeRequest);
    };

    if let Some(response) =
        build_dynamic_fast_path_response(&matched_route, url_str, &parsed.headers, parsed.keep_alive)?
    {
        return Ok(DispatchDecision::SpecializedResponse(response));
    };

    build_dispatch_envelope(
        &matched_route,
        method_code,
        path_str,
        url_str,
        &parsed.headers,
        body,
    )
    .map(DispatchDecision::BridgeRequest)
}

fn build_dispatch_request_owned(
    router: &Router,
    method: &[u8],
    target: &[u8],
    path: &[u8],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Option<Buffer>> {
    let Some(method_code) = method_code_from_bytes(method) else {
        return Ok(None);
    };

    let path_str = match std::str::from_utf8(path) {
        Ok(path_str) => path_str,
        Err(_) => return Ok(None),
    };
    let url_str = match std::str::from_utf8(target) {
        Ok(url_str) => url_str,
        Err(_) => return Ok(None),
    };

    // Security: strict path validation
    let normalized_path = normalize_runtime_path(path_str);
    if contains_path_traversal(&normalized_path) {
        return Ok(None);
    }

    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();

    let Some(matched_route) = router.match_route(method_code, normalized_path.as_ref()) else {
        return build_not_found_dispatch_envelope(
            method_code,
            path_str,
            url_str,
            &header_refs,
            body,
        )
        .map(Some);
    };

    build_dispatch_envelope(
        &matched_route,
        method_code,
        path_str,
        url_str,
        &header_refs,
        body,
    )
    .map(Some)
}

fn build_not_found_dispatch_envelope(
    method_code: u8,
    path: &str,
    url: &str,
    header_entries: &[(&str, &str)],
    body: &[u8],
) -> Result<Buffer> {
    let url_bytes = url.as_bytes();
    let path_bytes = path.as_bytes();
    let mut flags: u16 = 0;
    if url.contains('?') {
        flags |= REQUEST_FLAG_QUERY_PRESENT;
    }
    if !body.is_empty() {
        flags |= REQUEST_FLAG_BODY_PRESENT;
    }

    if url_bytes.len() > u32::MAX as usize {
        return Err(anyhow!("request url too large"));
    }
    if path_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request path too large"));
    }
    if header_entries.len() > u16::MAX as usize {
        return Err(anyhow!("too many headers"));
    }

    let mut frame = Vec::with_capacity(
        20 + url_bytes.len() + path_bytes.len() + header_entries.len() * 16 + body.len(),
    );
    frame.push(BRIDGE_VERSION);
    frame.push(method_code);
    push_u16(&mut frame, flags);
    push_u32(&mut frame, NOT_FOUND_HANDLER_ID);
    push_u32(&mut frame, url_bytes.len() as u32);
    push_u16(&mut frame, path_bytes.len() as u16);
    push_u16(&mut frame, 0);
    push_u16(&mut frame, header_entries.len() as u16);
    push_u32(&mut frame, body.len() as u32);
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);

    for (name, value) in header_entries {
        push_string_pair(&mut frame, name, value)?;
    }

    frame.extend_from_slice(body);
    Ok(Buffer::from(frame))
}

fn build_dispatch_envelope(
    matched_route: &MatchedRoute<'_, '_>,
    method_code: u8,
    path: &str,
    url: &str,
    header_entries: &[(&str, &str)],
    body: &[u8],
) -> Result<Buffer> {
    let include_url = matched_route.needs_url || matched_route.needs_query;
    let include_path = matched_route.needs_path;
    let url_bytes = if include_url { url.as_bytes() } else { b"" };
    let path_bytes = if include_path { path.as_bytes() } else { b"" };
    let mut flags: u16 = 0;
    if matched_route.needs_query && url.contains('?') {
        flags |= REQUEST_FLAG_QUERY_PRESENT;
    }
    if !body.is_empty() {
        flags |= REQUEST_FLAG_BODY_PRESENT;
    }

    if url_bytes.len() > u32::MAX as usize {
        return Err(anyhow!("request url too large"));
    }
    if path_bytes.len() > u16::MAX as usize {
        return Err(anyhow!("request path too large"));
    }
    if matched_route.param_values.len() > u16::MAX as usize {
        return Err(anyhow!("too many params"));
    }
    let selected_header_count = count_selected_headers(header_entries, matched_route);
    if selected_header_count > u16::MAX as usize {
        return Err(anyhow!("too many headers"));
    }

    let mut frame = Vec::with_capacity(
        20 + url_bytes.len() + path_bytes.len() + selected_header_count * 16 + body.len(),
    );
    frame.push(BRIDGE_VERSION);
    frame.push(method_code);
    push_u16(&mut frame, flags);
    push_u32(&mut frame, matched_route.handler_id);
    push_u32(&mut frame, url_bytes.len() as u32);
    push_u16(&mut frame, path_bytes.len() as u16);
    push_u16(&mut frame, matched_route.param_values.len() as u16);
    push_u16(&mut frame, selected_header_count as u16);
    push_u32(&mut frame, body.len() as u32); // NEW: body length
    frame.extend_from_slice(url_bytes);
    frame.extend_from_slice(path_bytes);

    for value in matched_route.param_values.iter() {
        push_string_value(&mut frame, value)?;
    }

    if selected_header_count > 0 {
        for (name, value) in header_entries {
            if should_include_header(name, matched_route) {
                push_string_pair(&mut frame, name, value)?;
            }
        }
    }

    frame.extend_from_slice(body); // NEW: body bytes at end

    Ok(Buffer::from(frame))
}

fn count_selected_headers(
    header_entries: &[(&str, &str)],
    matched_route: &MatchedRoute<'_, '_>,
) -> usize {
    if matched_route.full_headers {
        return header_entries.len();
    }

    if matched_route.header_keys.is_empty() {
        return 0;
    }

    header_entries
        .iter()
        .filter(|(name, _)| should_include_header(name, matched_route))
        .count()
}

fn should_include_header(name: &str, matched_route: &MatchedRoute<'_, '_>) -> bool {
    if matched_route.full_headers {
        return true;
    }
    matched_route
        .header_keys
        .iter()
        .any(|target| target.as_ref().eq_ignore_ascii_case(name))
}

enum ResolvedDynamicValue {
    Missing,
    Single(String),
    Multi(Vec<String>),
}

fn build_dynamic_fast_path_response(
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    keep_alive: bool,
) -> Result<Option<Vec<u8>>> {
    let Some(fast_path) = matched_route.fast_path else {
        return Ok(None);
    };

    let mut query_cache: Option<Vec<(String, String)>> = None;
    let body = match &fast_path.response {
        DynamicFastPathResponse::Json(template) => {
            render_dynamic_json_body(template, matched_route, url, headers, &mut query_cache)?
        }
        DynamicFastPathResponse::Text(template) => {
            render_dynamic_text_body(template, matched_route, url, headers, &mut query_cache)
        }
    };

    Ok(Some(build_response_bytes_fast(
        fast_path.status,
        fast_path.headers.as_ref(),
        &body,
        keep_alive,
    )))
}

fn render_dynamic_json_body(
    template: &crate::analyzer::JsonTemplate,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> Result<Vec<u8>> {
    match &template.kind {
        JsonTemplateKind::Literal(bytes) => Ok(bytes.to_vec()),
        JsonTemplateKind::Object(fields) => {
            let mut output = Vec::with_capacity(fields.len() * 24 + 16);
            output.push(b'{');
            let mut wrote_field = false;

            for field in fields.iter() {
                match &field.value {
                    JsonValueTemplate::Literal(value_bytes) => {
                        if wrote_field {
                            output.push(b',');
                        }
                        output.extend_from_slice(field.key_prefix.as_ref());
                        output.extend_from_slice(value_bytes.as_ref());
                        wrote_field = true;
                    }
                    JsonValueTemplate::Dynamic(source) => {
                        let resolved =
                            resolve_dynamic_value(source, matched_route, url, headers, query_cache);
                        match resolved {
                            ResolvedDynamicValue::Missing => {}
                            ResolvedDynamicValue::Single(value) => {
                                if wrote_field {
                                    output.push(b',');
                                }
                                output.extend_from_slice(field.key_prefix.as_ref());
                                append_json_string(&mut output, value.as_str());
                                wrote_field = true;
                            }
                            ResolvedDynamicValue::Multi(values) => {
                                if wrote_field {
                                    output.push(b',');
                                }
                                output.extend_from_slice(field.key_prefix.as_ref());
                                output.push(b'[');
                                for (index, value) in values.iter().enumerate() {
                                    if index > 0 {
                                        output.push(b',');
                                    }
                                    append_json_string(&mut output, value.as_str());
                                }
                                output.push(b']');
                                wrote_field = true;
                            }
                        }
                    }
                }
            }

            output.push(b'}');
            Ok(output)
        }
    }
}

fn render_dynamic_text_body(
    template: &crate::analyzer::TextTemplate,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> Vec<u8> {
    let mut output = String::new();
    for segment in template.segments.iter() {
        match segment {
            TextSegment::Literal(value) => output.push_str(value.as_ref()),
            TextSegment::Dynamic(source) => match resolve_dynamic_value(
                source,
                matched_route,
                url,
                headers,
                query_cache,
            ) {
                ResolvedDynamicValue::Missing => output.push_str("undefined"),
                ResolvedDynamicValue::Single(value) => output.push_str(value.as_str()),
                ResolvedDynamicValue::Multi(values) => {
                    for (index, value) in values.iter().enumerate() {
                        if index > 0 {
                            output.push(',');
                        }
                        output.push_str(value.as_str());
                    }
                }
            },
        }
    }

    output.into_bytes()
}

fn resolve_dynamic_value(
    source: &crate::analyzer::DynamicValueSource,
    matched_route: &MatchedRoute<'_, '_>,
    url: &str,
    headers: &[(&str, &str)],
    query_cache: &mut Option<Vec<(String, String)>>,
) -> ResolvedDynamicValue {
    match source.kind {
        DynamicValueSourceKind::Param => {
            if let Some(value) = lookup_param_value(matched_route, source.key.as_ref()) {
                return ResolvedDynamicValue::Single(value.to_string());
            }
            ResolvedDynamicValue::Missing
        }
        DynamicValueSourceKind::Header => {
            if let Some(value) = lookup_header_value(headers, source.key.as_ref()) {
                return ResolvedDynamicValue::Single(value.to_string());
            }
            ResolvedDynamicValue::Missing
        }
        DynamicValueSourceKind::Query => {
            let entries = query_entries(url, query_cache);
            lookup_query_value(entries.as_slice(), source.key.as_ref())
        }
    }
}

fn lookup_param_value<'m, 'r, 'p>(
    matched_route: &'m MatchedRoute<'r, 'p>,
    key: &str,
) -> Option<&'p str> {
    for (index, name) in matched_route.param_names.iter().enumerate() {
        if name.as_ref() == key {
            return matched_route.param_values.get(index).copied();
        }
    }
    None
}

fn lookup_header_value<'a>(headers: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(key).then_some(*value))
}

fn query_entries<'a>(
    url: &str,
    cache: &'a mut Option<Vec<(String, String)>>,
) -> &'a Vec<(String, String)> {
    if cache.is_none() {
        let parsed = if let Some(query_start) = url.find('?') {
            let query = &url[query_start + 1..];
            form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        *cache = Some(parsed);
    }

    cache.as_ref().expect("query cache must be initialized")
}

fn lookup_query_value(entries: &[(String, String)], key: &str) -> ResolvedDynamicValue {
    let mut values: Vec<String> = Vec::new();
    for (entry_key, entry_value) in entries.iter() {
        if entry_key == key {
            values.push(entry_value.clone());
        }
    }

    match values.len() {
        0 => ResolvedDynamicValue::Missing,
        1 => ResolvedDynamicValue::Single(values.pop().unwrap_or_default()),
        _ => ResolvedDynamicValue::Multi(values),
    }
}

fn append_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\n' => output.extend_from_slice(br#"\n"#),
            '\r' => output.extend_from_slice(br#"\r"#),
            '\t' => output.extend_from_slice(br#"\t"#),
            '\x08' => output.extend_from_slice(br#"\b"#),
            '\x0C' => output.extend_from_slice(br#"\f"#),
            other if other.is_control() => {
                let escaped = format!("\\u{:04x}", other as u32);
                output.extend_from_slice(escaped.as_bytes());
            }
            other => {
                let mut buf = [0u8; 4];
                output.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    output.push(b'"');
}

fn build_response_bytes_fast(
    status: u16,
    headers: &[(Box<str>, Box<str>)],
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = body.len();

    let mut total_size =
        9 + 3 + 1 + reason.len() + 2 + 16 + count_digits(body_len) + 2 + 12 + connection.len() + 2;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        total_size += name.len() + 2 + value.len() + 2;
    }

    total_size += 2 + body_len;

    let mut output = Vec::with_capacity(total_size);
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, body_len);
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body);
    output
}

// ─── Response Writing ─────────────────────────────────────────────────────────

async fn write_exact_static_response(
    stream: &mut TcpStream,
    static_route: &ExactStaticRoute,
    keep_alive: bool,
) -> Result<()> {
    let response = if keep_alive {
        static_route.keep_alive_response.clone()
    } else {
        static_route.close_response.clone()
    };

    let (write_result, _) = stream.write_all(response).await;
    write_result?;
    Ok(())
}

async fn write_dynamic_dispatch_response(
    stream: &mut TcpStream,
    dispatcher: &JsDispatcher,
    request: Buffer,
    keep_alive: bool,
) -> Result<()> {
    match dispatcher.dispatch(request) {
        Ok(response) => {
            match build_http_response_from_dispatch(response.as_ref(), keep_alive) {
                Ok(http_response) => {
                    let (write_result, _) = stream.write_all(http_response).await;
                    write_result?;
                }
                Err(_) => {
                    // Security: sanitized error — no internal details
                    let response = build_error_response_bytes(
                        500,
                        b"{\"error\":\"Internal Server Error\"}",
                        keep_alive,
                    );
                    let (write_result, _) = stream.write_all(response).await;
                    write_result?;
                }
            }
        }
        Err(_) => {
            // Security: sanitized error — no internal details
            let response = build_error_response_bytes(
                503,
                b"{\"error\":\"Service Unavailable\"}",
                keep_alive,
            );
            let (write_result, _) = stream.write_all(response).await;
            write_result?;
        }
    }
    Ok(())
}

/// Build HTTP response bytes directly from the binary dispatch envelope,
/// avoiding all intermediate String/Bytes allocations.
fn build_http_response_from_dispatch(dispatch_bytes: &[u8], keep_alive: bool) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let status = read_u16(dispatch_bytes, &mut offset)?;
    let header_count = read_u16(dispatch_bytes, &mut offset)? as usize;
    let body_length = read_u32(dispatch_bytes, &mut offset)? as usize;

    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };

    // Conservative estimate: framing overhead + all dispatch bytes
    let mut output = Vec::with_capacity(dispatch_bytes.len() + 128);

    // Status line
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Mandatory headers
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, body_length);
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    // User headers — read directly from binary without String allocation
    for _ in 0..header_count {
        let name_len = read_u8(dispatch_bytes, &mut offset)? as usize;
        let value_len = read_u16(dispatch_bytes, &mut offset)? as usize;

        if offset + name_len + value_len > dispatch_bytes.len() {
            return Err(anyhow!("response envelope truncated"));
        }

        let name_bytes = &dispatch_bytes[offset..offset + name_len];
        offset += name_len;
        let value_bytes = &dispatch_bytes[offset..offset + value_len];
        offset += value_len;

        // Skip headers we already wrote
        if name_bytes.eq_ignore_ascii_case(b"content-length")
            || name_bytes.eq_ignore_ascii_case(b"connection")
        {
            continue;
        }

        // Security: CRLF injection check
        if name_bytes.iter().any(|&b| b == b'\r' || b == b'\n')
            || value_bytes.iter().any(|&b| b == b'\r' || b == b'\n')
        {
            continue;
        }

        output.extend_from_slice(name_bytes);
        output.extend_from_slice(b": ");
        output.extend_from_slice(value_bytes);
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");

    // Body
    if offset + body_length > dispatch_bytes.len() {
        return Err(anyhow!("response body truncated"));
    }
    output.extend_from_slice(&dispatch_bytes[offset..offset + body_length]);

    Ok(output)
}

async fn write_not_found_response(stream: &mut TcpStream, keep_alive: bool) -> Result<()> {
    let response = if keep_alive {
        Bytes::from_static(NOT_FOUND_RESPONSE_KEEP_ALIVE)
    } else {
        Bytes::from_static(NOT_FOUND_RESPONSE_CLOSE)
    };
    let (write_result, _) = stream.write_all(response).await;
    write_result?;
    Ok(())
}

/// Build a simple error response without going through the JS bridge
fn build_error_response_bytes(status: u16, body: &[u8], keep_alive: bool) -> Vec<u8> {
    build_response_bytes(
        status,
        &[(
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        )],
        Bytes::copy_from_slice(body),
        keep_alive,
    )
}

/// Optimized response builder: pre-calculates size and writes in a single pass
fn build_response_bytes(
    status: u16,
    headers: &[(String, String)],
    body: Bytes,
    keep_alive: bool,
) -> Vec<u8> {
    let reason = status_reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let body_len = body.len();

    // Pre-calculate total size to avoid reallocations
    // "HTTP/1.1 " + status(3) + " " + reason + "\r\n" + "content-length: " + digits + "\r\n" + "connection: " + conn + "\r\n"
    let mut total_size =
        9 + 3 + 1 + reason.len() + 2 + 16 + count_digits(body_len) + 2 + 12 + connection.len() + 2;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        // Security: skip headers with CRLF injection
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        total_size += name.len() + 2 + value.len() + 2;
    }

    total_size += 2 + body_len; // final \r\n + body

    let mut output = Vec::with_capacity(total_size);

    // Status line
    output.extend_from_slice(b"HTTP/1.1 ");
    write_u16(&mut output, status);
    output.push(b' ');
    output.extend_from_slice(reason.as_bytes());
    output.extend_from_slice(b"\r\n");

    // Mandatory headers
    output.extend_from_slice(b"content-length: ");
    write_usize(&mut output, body_len);
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(b"connection: ");
    output.extend_from_slice(connection.as_bytes());
    output.extend_from_slice(b"\r\n");

    // User headers
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        if name.contains('\r')
            || name.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            continue;
        }
        output.extend_from_slice(name.as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(body.as_ref());
    output
}

// ─── Security Utilities ───────────────────────────────────────────────────────

/// Check for path traversal attempts (../, ..\, etc.)
fn contains_path_traversal(path: &str) -> bool {
    // Decode percent-encoded dots
    let decoded = path.replace("%2e", ".").replace("%2E", ".");

    // Check for traversal patterns
    decoded.contains("/../")
        || decoded.contains("\\..\\")
        || decoded.ends_with("/..")
        || decoded.ends_with("\\..")
        || decoded.starts_with("../")
        || decoded.starts_with("..\\")
        || decoded == ".."
}

/// RFC 8259 compliant JSON string escaping — handles ALL control characters
#[allow(dead_code)]
pub(crate) fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\x08' => output.push_str("\\b"),
            '\x0C' => output.push_str("\\f"),
            c if c.is_control() => {
                output.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => output.push(c),
        }
    }
    output
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn method_code_from_bytes(method: &[u8]) -> Option<u8> {
    match method {
        b"GET" => Some(1),
        b"POST" => Some(2),
        b"PUT" => Some(3),
        b"DELETE" => Some(4),
        b"PATCH" => Some(5),
        b"OPTIONS" => Some(6),
        b"HEAD" => Some(7),
        _ => None,
    }
}

fn drain_consumed_bytes(buffer: &mut Vec<u8>, consumed: usize) {
    if consumed >= buffer.len() {
        buffer.clear();
        return;
    }

    let remaining = buffer.len() - consumed;
    buffer.copy_within(consumed.., 0);
    buffer.truncate(remaining);
}

fn bind_listener(
    options: &NativeListenOptions,
    server_config: &HttpServerConfig,
) -> Result<TcpListener> {
    let host = options
        .host
        .as_deref()
        .unwrap_or(server_config.default_host.as_str());
    let bind_addr = resolve_socket_addr(host, options.port)
        .with_context(|| format!("failed to resolve bind address {host}:{}", options.port))?;
    let listener_opts = ListenerOpts::new()
        .reuse_addr(true)
        .reuse_port(true)
        .backlog(options.backlog.unwrap_or(server_config.default_backlog));

    TcpListener::bind_with_config(bind_addr, &listener_opts)
        .with_context(|| format!("failed to bind TCP listener on {bind_addr}"))
}

fn resolve_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("unable to resolve {host}:{port}"))
}

fn validate_manifest(manifest: &ManifestInput) -> Result<()> {
    if manifest.version != 1 {
        return Err(anyhow!("Unsupported manifest version {}", manifest.version));
    }

    Ok(())
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    memmem::find(bytes, b"\r\n\r\n")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn trim_ascii_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn normalize_runtime_path(path: &str) -> Cow<'_, str> {
    if path == "/" || !path.ends_with('/') {
        return Cow::Borrowed(path);
    }

    Cow::Owned(crate::analyzer::normalize_path(path))
}

fn config_string(
    input: Option<&HttpServerConfigInput>,
    pick: impl Fn(&HttpServerConfigInput) -> Option<&str>,
    fallback: &str,
) -> String {
    input.and_then(pick).unwrap_or(fallback).to_string()
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

/// Fast integer-to-string for small values — uses stack-allocated itoa buffer
#[inline(always)]
fn write_usize(output: &mut Vec<u8>, value: usize) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

#[inline(always)]
fn write_u16(output: &mut Vec<u8>, value: u16) {
    let mut buf = itoa::Buffer::new();
    output.extend_from_slice(buf.format(value).as_bytes());
}

fn count_digits(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    while n > 0 {
        count += 1;
        n /= 10;
    }
    count
}

fn push_string_pair(frame: &mut Vec<u8>, name: &str, value: &str) -> Result<()> {
    if name.len() > u8::MAX as usize {
        return Err(anyhow!("field name too long"));
    }
    if value.len() > u16::MAX as usize {
        return Err(anyhow!("field value too long"));
    }

    frame.push(name.len() as u8);
    push_u16(frame, value.len() as u16);
    frame.extend_from_slice(name.as_bytes());
    frame.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_string_value(frame: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(anyhow!("field value too long"));
    }

    push_u16(frame, value.len() as u16);
    frame.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u16(frame: &mut Vec<u8>, value: u16) {
    frame.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(frame: &mut Vec<u8>, value: u32) {
    frame.extend_from_slice(&value.to_le_bytes());
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    if *offset + 1 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16> {
    if *offset + 2 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = u16::from_le_bytes([bytes[*offset], bytes[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > bytes.len() {
        return Err(anyhow!("response envelope truncated"));
    }

    let value = u32::from_le_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

unsafe fn read_required_utf8(value: *const u8, len: usize, field: &str) -> Result<String> {
    if value.is_null() {
        return Err(anyhow!("{field} pointer was null"));
    }

    let bytes = slice::from_raw_parts(value, len);
    std::str::from_utf8(bytes)
        .map(|text| text.to_owned())
        .map_err(|_| anyhow!("{field} was not valid UTF-8"))
}

unsafe fn read_optional_utf8(value: *const u8, len: usize, field: &str) -> Result<Option<String>> {
    if value.is_null() || len == 0 {
        return Ok(None);
    }

    read_required_utf8(value, len, field).map(Some)
}

fn clear_last_error() {
    let mut slot = LAST_ERROR.lock().expect("last error mutex poisoned");
    *slot = None;
}

fn set_last_error(message: impl AsRef<str>) {
    let mut cleaned = message.as_ref().replace('\0', " ");
    if cleaned.is_empty() {
        cleaned = "unknown native error".to_string();
    }

    let message = CString::new(cleaned).expect("nul bytes already removed");
    let mut slot = LAST_ERROR.lock().expect("last error mutex poisoned");
    *slot = Some(message);
}

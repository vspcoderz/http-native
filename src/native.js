import { Buffer } from "node:buffer";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CString, dlopen, suffix, toArrayBuffer } from "bun:ffi";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const textEncoder = new TextEncoder();
const INTERNAL_ERROR_BODY = Buffer.from('{"error":"Internal Server Error"}', "utf8");
const DISPATCH_BATCH_IDLE_MS = Number.parseInt(
  process.env.HTTP_NATIVE_DISPATCH_IDLE_MS ?? "0",
  10,
);
const DISPATCH_BATCH_MAX_ITEMS = Number.parseInt(
  process.env.HTTP_NATIVE_DISPATCH_BATCH_MAX_ITEMS ?? "256",
  10,
);
const platformNativeExtension =
  process.platform === "darwin"
    ? "dylib"
    : process.platform === "win32"
      ? "dll"
      : "so";

let cachedNativeModule = null;

function isNullPointer(value) {
  return value === null || value === undefined || value === 0 || value === 0n;
}

function consumeCString(symbols, cStringPtr) {
  if (isNullPointer(cStringPtr)) {
    return "";
  }

  const value = new CString(cStringPtr).toString();
  symbols.http_native_string_free(cStringPtr);
  return value;
}

function consumeLastError(symbols) {
  const message = consumeCString(symbols, symbols.http_native_take_last_error());
  return message || "unknown native error";
}

function encodeInternalErrorEnvelope(status = 500) {
  const envelope = new Uint8Array(8 + INTERNAL_ERROR_BODY.length);
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  view.setUint16(0, status, true);
  view.setUint16(2, 0, true);
  view.setUint32(4, INTERNAL_ERROR_BODY.length, true);
  envelope.set(INTERNAL_ERROR_BODY, 8);
  return envelope;
}

function normalizeResponseEnvelopeBytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  throw new TypeError("dispatcher must return a Uint8Array/Buffer response envelope");
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function idleYield() {
  const idleMs = Math.max(0, DISPATCH_BATCH_IDLE_MS | 0);
  if (typeof Bun?.sleep === "function") {
    await Bun.sleep(idleMs);
  } else if (idleMs === 0) {
    await Promise.resolve();
  } else {
    await sleep(idleMs);
  }
}

function decodeDispatchBatch(symbols, batchPtr) {
  const sizePrefix = new Uint8Array(toArrayBuffer(batchPtr, 0, 4));
  const payloadLength = new DataView(
    sizePrefix.buffer,
    sizePrefix.byteOffset,
    sizePrefix.byteLength,
  ).getUint32(0, true);

  if (payloadLength === 0) {
    return [];
  }

  const payloadBytes = new Uint8Array(toArrayBuffer(batchPtr, 4, payloadLength));
  const view = new DataView(
    payloadBytes.buffer,
    payloadBytes.byteOffset,
    payloadBytes.byteLength,
  );
  let offset = 0;

  if (payloadBytes.byteLength < 4) {
    throw new Error("native dispatch batch truncated");
  }

  const itemCount = view.getUint32(offset, true);
  offset += 4;
  const jobs = new Array(itemCount);

  for (let index = 0; index < itemCount; index += 1) {
    if (offset + 12 > payloadBytes.byteLength) {
      throw new Error("native dispatch batch item header truncated");
    }
    const requestId = view.getBigUint64(offset, true);
    offset += 8;
    const requestLength = view.getUint32(offset, true);
    offset += 4;

    if (offset + requestLength > payloadBytes.byteLength) {
      throw new Error("native dispatch batch item payload truncated");
    }

    const requestView = new Uint8Array(
      payloadBytes.buffer,
      payloadBytes.byteOffset + offset,
      requestLength,
    );
    const requestEnvelope = Buffer.from(requestView);
    offset += requestLength;

    jobs[index] = {
      requestId,
      requestEnvelope,
    };
  }

  if (offset !== payloadBytes.byteLength) {
    throw new Error("native dispatch batch has trailing bytes");
  }

  return jobs;
}

async function processDispatchJob(symbols, serverHandlePtr, dispatcher, job) {
  let responseBytes;
  try {
    const result = dispatcher(job.requestEnvelope);
    responseBytes = normalizeResponseEnvelopeBytes(await Promise.resolve(result));
  } catch {
    responseBytes = encodeInternalErrorEnvelope(500);
  }

  const submitted = symbols.http_native_submit_dispatch_response(
    serverHandlePtr,
    job.requestId,
    responseBytes,
    responseBytes.byteLength,
  );
  if (!submitted) {
    const message = consumeLastError(symbols);
    if (message && !message.includes("not pending")) {
      throw new Error(message);
    }
  }
}

function createDispatchPump(symbols, serverHandlePtr, dispatcher) {
  let stopped = false;

  const loopPromise = (async () => {
    while (!stopped) {
      const batchPtr = symbols.http_native_poll_dispatch_batch(
        serverHandlePtr,
        Math.max(1, DISPATCH_BATCH_MAX_ITEMS | 0),
      );

      if (isNullPointer(batchPtr)) {
        await idleYield();
        continue;
      }

      let jobs = [];
      try {
        jobs = decodeDispatchBatch(symbols, batchPtr);
      } catch (error) {
        const nativeError = consumeLastError(symbols);
        throw new Error(
          nativeError
            ? `failed to decode dispatch batch: ${nativeError}`
            : `failed to decode dispatch batch: ${error instanceof Error ? error.message : String(error)}`,
        );
      } finally {
        symbols.http_native_dispatch_batch_free(serverHandlePtr, batchPtr);
      }

      if (jobs.length === 0) {
        await idleYield();
        continue;
      }

      await Promise.all(jobs.map((job) => processDispatchJob(symbols, serverHandlePtr, dispatcher, job)));
    }
  })();

  return {
    async stop() {
      stopped = true;
      await Promise.resolve(loopPromise).catch(() => {});
    },
  };
}

function buildNativePathCandidates(configuredPath) {
  const candidates = [];
  const pushCandidate = (candidatePath) => {
    if (!candidatePath) {
      return;
    }

    const absolutePath = resolve(rootDir, candidatePath);
    if (!candidates.includes(absolutePath)) {
      candidates.push(absolutePath);
    }
  };

  if (configuredPath) {
    pushCandidate(configuredPath);

    if (configuredPath.endsWith(".node")) {
      const nodeBase = configuredPath.slice(0, -".node".length);
      pushCandidate(`${nodeBase}.${platformNativeExtension}`);

      if (nodeBase.endsWith(".release")) {
        pushCandidate(`${nodeBase.slice(0, -".release".length)}.${platformNativeExtension}`);
      } else if (nodeBase.endsWith(".debug")) {
        pushCandidate(`${nodeBase.slice(0, -".debug".length)}.${platformNativeExtension}`);
      }
    }

    return candidates;
  }

  pushCandidate(`http-native.release.${suffix}`);
  pushCandidate(`http-native.${suffix}`);
  pushCandidate(`http-native.debug.${suffix}`);
  return candidates;
}

function loadFfiNative() {
  if (cachedNativeModule) {
    return cachedNativeModule;
  }

  const configuredPath =
    process.env.HTTP_NATIVE_NATIVE_PATH ?? process.env.HTTP_NATIVE_NODE_PATH;
  const candidatePaths = buildNativePathCandidates(configuredPath);
  const nativeModulePath = candidatePaths.find((candidatePath) =>
    existsSync(candidatePath),
  );

  if (!nativeModulePath) {
    throw new Error(
      `Native module not found. Tried: ${candidatePaths.join(", ")}. Build it first with "bun run build".`,
    );
  }

  const library = dlopen(nativeModulePath, {
    http_native_start_server: {
      returns: "ptr",
      args: ["buffer", "usize", "buffer", "usize", "u16", "i32"],
    },
    http_native_poll_dispatch_batch: {
      returns: "ptr",
      args: ["ptr", "u32"],
    },
    http_native_dispatch_batch_free: {
      returns: "void",
      args: ["ptr", "ptr"],
    },
    http_native_submit_dispatch_response: {
      returns: "bool",
      args: ["ptr", "u64", "buffer", "usize"],
    },
    http_native_take_last_error: {
      returns: "ptr",
      args: [],
    },
    http_native_string_free: {
      returns: "void",
      args: ["ptr"],
    },
    http_native_server_snapshot_json: {
      returns: "ptr",
      args: ["ptr"],
    },
    http_native_server_close: {
      returns: "bool",
      args: ["ptr"],
    },
    http_native_server_free: {
      returns: "void",
      args: ["ptr"],
    },
  });

  const { symbols } = library;

  cachedNativeModule = {
    startServer(manifestJson, dispatcher, options) {
      if (typeof dispatcher !== "function") {
        throw new TypeError("native dispatcher must be a function");
      }

      const host = String(options.host ?? "127.0.0.1");
      const port = Number(options.port ?? 3000);
      const backlog = Number(options.backlog ?? 2048);
      const manifestBytes = textEncoder.encode(String(manifestJson));
      const hostBytes = textEncoder.encode(host);
      const serverHandlePtr = symbols.http_native_start_server(
        manifestBytes,
        manifestBytes.byteLength,
        hostBytes,
        hostBytes.byteLength,
        Math.max(0, Math.min(65535, Math.trunc(port))),
        Math.trunc(backlog),
      );

      if (isNullPointer(serverHandlePtr)) {
        throw new Error(consumeLastError(symbols));
      }

      const snapshotPtr = symbols.http_native_server_snapshot_json(serverHandlePtr);
      if (isNullPointer(snapshotPtr)) {
        symbols.http_native_server_free(serverHandlePtr);
        throw new Error(consumeLastError(symbols));
      }

      const snapshotRaw = consumeCString(symbols, snapshotPtr);
      let snapshot;
      try {
        snapshot = JSON.parse(snapshotRaw);
      } catch {
        symbols.http_native_server_free(serverHandlePtr);
        throw new Error("native server returned invalid snapshot payload");
      }

      const dispatchPump = createDispatchPump(symbols, serverHandlePtr, dispatcher);
      let released = false;

      return {
        host: snapshot.host,
        port: snapshot.port,
        url: snapshot.url,
        async close() {
          if (released) {
            return;
          }

          released = true;
          let closeError = null;
          const closed = symbols.http_native_server_close(serverHandlePtr);
          if (!closed) {
            closeError = new Error(consumeLastError(symbols));
          }

          await dispatchPump.stop();
          symbols.http_native_server_free(serverHandlePtr);

          if (closeError) {
            throw closeError;
          }
        },
      };
    },
  };

  return cachedNativeModule;
}

export function loadNativeModule() {
  if (!globalThis.Bun) {
    throw new Error("The experimental bun:ffi bridge requires Bun runtime.");
  }

  return loadFfiNative();
}

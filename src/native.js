import { Buffer } from "node:buffer";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CString, JSCallback, dlopen, ptr, suffix, toArrayBuffer } from "bun:ffi";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const textEncoder = new TextEncoder();
const RESPONSE_FRAME_PREFIX_BYTES = 4;
const INTERNAL_ERROR_BODY = Buffer.from('{"error":"Internal Server Error"}', "utf8");
const responseFrameRefs = new Set();

let cachedNativeModule = null;

function isNullPointer(value) {
  return value === null || value === undefined || value === 0 || value === 0n;
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

function encodeResponseFrame(payload) {
  const bytes = payload instanceof Uint8Array ? payload : Buffer.from(payload ?? []);
  const frame = new Uint8Array(RESPONSE_FRAME_PREFIX_BYTES + bytes.byteLength);
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  view.setUint32(0, bytes.byteLength, true);
  frame.set(bytes, RESPONSE_FRAME_PREFIX_BYTES);
  return frame;
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

function normalizeResponseEnvelopeBytes(value) {
  if (value instanceof Uint8Array) {
    return value;
  }

  throw new TypeError("dispatcher must return a Uint8Array/Buffer response envelope");
}

function createDispatchCallback(dispatcher) {
  return new JSCallback(
    (requestPtr, requestLength) => {
      try {
        const requestBytes = new Uint8Array(
          toArrayBuffer(requestPtr, 0, Number(requestLength)),
        );
        const result = dispatcher(Buffer.from(requestBytes));
        if (result && typeof result.then === "function") {
          throw new TypeError(
            "experimental bun:ffi bridge does not support async route/middleware handlers yet",
          );
        }

        const responseBytes = normalizeResponseEnvelopeBytes(result);
        const responseFrame = encodeResponseFrame(responseBytes);
        responseFrameRefs.add(responseFrame);
        queueMicrotask(() => {
          responseFrameRefs.delete(responseFrame);
        });
        return ptr(responseFrame);
      } catch {
        const fallbackFrame = encodeResponseFrame(encodeInternalErrorEnvelope(500));
        responseFrameRefs.add(fallbackFrame);
        queueMicrotask(() => {
          responseFrameRefs.delete(fallbackFrame);
        });
        return ptr(fallbackFrame);
      }
    },
    {
      args: ["ptr", "usize"],
      returns: "ptr",
    },
  );
}

function loadFfiNative() {
  if (cachedNativeModule) {
    return cachedNativeModule;
  }

  const configuredPath =
    process.env.HTTP_NATIVE_NATIVE_PATH ?? process.env.HTTP_NATIVE_NODE_PATH;
  const nativeModulePath = configuredPath
    ? resolve(rootDir, configuredPath)
    : resolve(rootDir, `http-native.${suffix}`);

  if (!existsSync(nativeModulePath)) {
    throw new Error(
      `Native module not found at ${nativeModulePath}. Build it first with "bun run build".`,
    );
  }

  const library = dlopen(nativeModulePath, {
    http_native_start_server: {
      returns: "ptr",
      args: ["buffer", "usize", "function", "buffer", "usize", "u16", "i32"],
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
      const dispatchCallback = createDispatchCallback(dispatcher);
      const serverHandlePtr = symbols.http_native_start_server(
        manifestBytes,
        manifestBytes.byteLength,
        dispatchCallback,
        hostBytes,
        hostBytes.byteLength,
        Math.max(0, Math.min(65535, Math.trunc(port))),
        Math.trunc(backlog),
      );

      if (isNullPointer(serverHandlePtr)) {
        dispatchCallback.close();
        throw new Error(consumeLastError(symbols));
      }

      const snapshotPtr = symbols.http_native_server_snapshot_json(serverHandlePtr);
      if (isNullPointer(snapshotPtr)) {
        symbols.http_native_server_free(serverHandlePtr);
        dispatchCallback.close();
        throw new Error(consumeLastError(symbols));
      }

      const snapshotRaw = consumeCString(symbols, snapshotPtr);
      let snapshot;
      try {
        snapshot = JSON.parse(snapshotRaw);
      } catch {
        symbols.http_native_server_free(serverHandlePtr);
        dispatchCallback.close();
        throw new Error("native server returned invalid snapshot payload");
      }

      let released = false;
      return {
        host: snapshot.host,
        port: snapshot.port,
        url: snapshot.url,
        close() {
          if (released) {
            return;
          }

          released = true;
          const closed = symbols.http_native_server_close(serverHandlePtr);
          symbols.http_native_server_free(serverHandlePtr);
          dispatchCallback.close();
          if (!closed) {
            throw new Error(consumeLastError(symbols));
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

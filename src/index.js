import { Buffer } from "node:buffer";

import {
  analyzeRequestAccess,
  compileRouteShape,
  createJsonSerializer,
  createRequestFactory,
  decodeRequestEnvelope,
  encodeResponseEnvelope,
  METHOD_CODES,
  mergeRequestAccessPlans,
  ROUTE_KIND,
  releaseRequestObject,
} from "./bridge.js";
import { loadNativeModule } from "./native.js";
import defaultHttpServerConfig, {
  normalizeHttpServerConfig,
} from "./http-server.config.js";
import { createRuntimeOptimizer } from "../opt/runtime.js";

const HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
const ACTIVE_NATIVE_SERVERS = new Set();
const EMPTY_BUFFER = Buffer.alloc(0);
const EMPTY_ARRAY = Object.freeze([]);
const NOOP_NEXT = () => undefined;
const ROUTE_CACHE_PROMOTE_HITS = 16;
let nativeProcessKeepAlive = null;
const ERROR_REQUEST_PLAN = Object.freeze({
  method: true,
  path: true,
  url: true,
  fullParams: false,
  fullQuery: true,
  fullHeaders: true,
  paramKeys: new Set(),
  queryKeys: new Set(),
  headerKeys: new Set(),
  dispatchKind: "generic_fallback",
  jsonFastPath: "fallback",
});

// ─── Path Normalization ───────────────────────────────────────────────────────

function normalizePathPrefix(path) {
  if (path === "/") {
    return "/";
  }

  const trimmed = String(path).replace(/\/+$/, "");
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function retainNativeProcessLifetime() {
  if (nativeProcessKeepAlive) {
    return;
  }

  nativeProcessKeepAlive = setInterval(() => {}, 1 << 30);
}

function releaseNativeProcessLifetime() {
  if (!nativeProcessKeepAlive || ACTIVE_NATIVE_SERVERS.size > 0) {
    return;
  }

  clearInterval(nativeProcessKeepAlive);
  nativeProcessKeepAlive = null;
}

function normalizeRoutePath(method, path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new TypeError(`Route path for ${method} must start with "/"`);
  }

  return normalizePathPrefix(path);
}

function pathPrefixMatches(pathPrefix, requestPath) {
  if (pathPrefix === "/") {
    return true;
  }

  return requestPath === pathPrefix || requestPath.startsWith(`${pathPrefix}/`);
}

function normalizeContentType(type) {
  if (type.includes("/")) {
    return type;
  }

  if (type === "json") {
    return "application/json; charset=utf-8";
  }

  if (type === "html") {
    return "text/html; charset=utf-8";
  }

  if (type === "text") {
    return "text/plain; charset=utf-8";
  }

  return type;
}



const RESPONSE_POOL_MAX = 512;
const responseStatePool = [];
const responseObjectPool = [];
const DEFAULT_JSON_SERIALIZER = createJsonSerializer("fallback");

function acquireResponseState() {
  const pooled = responseStatePool.pop();
  if (pooled) {
    pooled.status = 200;
    // Reset headers — use null-prototype object for security
    for (const key in pooled.headers) {
      delete pooled.headers[key];
    }
    pooled.body = EMPTY_BUFFER;
    pooled.finished = false;
    // Reset locals
    for (const key in pooled.locals) {
      delete pooled.locals[key];
    }
    return pooled;
  }

  return {
    status: 200,
    headers: Object.create(null),
    body: EMPTY_BUFFER,
    finished: false,
    locals: Object.create(null),
  };
}

function releaseResponseState(state) {
  if (responseStatePool.length < RESPONSE_POOL_MAX) {
    responseStatePool.push(state);
  }
}

const RESPONSE_PROTO = {
  get finished() {
    return this._state.finished;
  },

  status(code) {
    this._state.status = Number(code);
    return this;
  },

  set(name, value) {
    // Security: validate header name/value for CRLF injection
    const headerName = String(name).toLowerCase();
    const headerValue = String(value);
    if (
      headerName.includes("\r") ||
      headerName.includes("\n") ||
      headerValue.includes("\r") ||
      headerValue.includes("\n")
    ) {
      return this; // Silently reject — security
    }
    this._state.headers[headerName] = headerValue;
    return this;
  },

  header(name, value) {
    return this.set(name, value);
  },

  get(name) {
    return this._state.headers[String(name).toLowerCase()];
  },

  type(value) {
    return this.set("content-type", normalizeContentType(String(value)));
  },

  json(data) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    if (!state.headers["content-type"]) {
      state.headers["content-type"] = "application/json; charset=utf-8";
    }

    state.body = this._jsonSerializer(data);
    state.finished = true;
    return this;
  },

  send(data) {
    const state = this._state;
    if (state.finished) {
      return this;
    }

    if (Buffer.isBuffer(data) || data instanceof Uint8Array) {
      if (!state.headers["content-type"]) {
        state.headers["content-type"] = "application/octet-stream";
      }
      state.body = Buffer.isBuffer(data)
        ? data
        : Buffer.from(data.buffer, data.byteOffset, data.byteLength);
    } else if (typeof data === "string") {
      if (!state.headers["content-type"]) {
        state.headers["content-type"] = "text/plain; charset=utf-8";
      }
      state.body = Buffer.from(data, "utf8");
    } else if (data === undefined || data === null) {
      state.body = EMPTY_BUFFER;
    } else {
      return this.json(data);
    }

    state.finished = true;
    return this;
  },

  sendStatus(code) {
    this.status(code);
    const state = this._state;
    if (!state.headers["content-type"]) {
      state.headers["content-type"] = "text/plain; charset=utf-8";
    }
    return this.send(String(code));
  },
};

function createResponseEnvelope(jsonSerializer = DEFAULT_JSON_SERIALIZER) {
  const state = acquireResponseState();
  const response = responseObjectPool.pop() ?? Object.create(RESPONSE_PROTO);
  response._state = state;
  response._jsonSerializer = jsonSerializer;
  response.locals = state.locals;

  return {
    response,
    snapshot() {
      return {
        status: state.status,
        headers: state.headers,
        body: state.body,
      };
    },
    release() {
      response.locals = null;
      response._jsonSerializer = DEFAULT_JSON_SERIALIZER;
      response._state = null;
      if (responseObjectPool.length < RESPONSE_POOL_MAX) {
        responseObjectPool.push(response);
      }
      releaseResponseState(state);
    },
  };
}

// ─── Compiled Middleware Runner ────────────────────────────────────────────────
//
// Generates an optimized runner that avoids function.length checks at runtime
// by pre-classifying middlewares during compilation.

function createMiddlewareRunner(middlewares) {
  if (middlewares.length === 0) {
    // Fast path: no middlewares — return a no-op
    return function noopMiddleware(_req, _res) {};
  }

  if (middlewares.length === 1) {
    // Fast path: single middleware — avoid dispatch overhead
    const mw = middlewares[0];
    if (mw.handler.length >= 3) {
      return function runSingleMiddleware(req, res) {
        return mw.handler(req, res, NOOP_NEXT);
      };
    }
    return function runSingleMiddleware(req, res) {
      return mw.handler(req, res);
    };
  }

  // Pre-classify each middleware as "next-aware" or "auto-advance"
  const classified = middlewares.map((mw) => ({
    handler: mw.handler,
    needsNext: mw.handler.length >= 3,
  }));

  return async function runCompiledMiddlewares(req, res) {
    let index = -1;

    async function dispatch(position) {
      if (position <= index) {
        throw new Error("Middleware next() called multiple times");
      }

      index = position;
      const middleware = classified[position];
      if (!middleware || res.finished) {
        return;
      }

      if (middleware.needsNext) {
        await middleware.handler(req, res, () => dispatch(position + 1));
        return;
      }

      await middleware.handler(req, res);
      if (!res.finished) {
        await dispatch(position + 1);
      }
    }

    await dispatch(0);
  };
}

// ─── Error Handling (Security-Hardened) ───────────────────────────────────────

function normalizeErrorStatus(error, fallbackStatus = 500) {
  const status = Number(error?.status ?? error?.statusCode ?? fallbackStatus);
  return Number.isInteger(status) && status >= 400 && status <= 599
    ? status
    : fallbackStatus;
}

function createHttpError(status, message, code) {
  const error = new Error(message);
  error.status = status;
  if (code) {
    error.code = code;
  }
  return error;
}

function buildDefaultErrorSnapshot(error, fallbackStatus = 500) {
  // Security: NEVER leak internal error details to the client
  const status = normalizeErrorStatus(error, fallbackStatus);
  const isProduction = process.env.NODE_ENV === "production";
  let body;

  if (status === 404) {
    body = {
      error: error?.message || "Route not found",
    };
  } else if (status >= 500) {
    body = isProduction
      ? { error: "Internal Server Error" }
      : {
          error: "Internal Server Error",
          detail: error instanceof Error ? error.message : String(error),
        };
  } else {
    body = {
      error:
        error instanceof Error && error.message
          ? error.message
          : `HTTP ${status}`,
    };
  }

  return {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
    body: Buffer.from(JSON.stringify(body), "utf8"),
  };
}

function serializeErrorResponse(error, fallbackStatus = 500) {
  return encodeResponseEnvelope(buildDefaultErrorSnapshot(error, fallbackStatus));
}

function isPromiseLike(value) {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
    typeof value.then === "function"
  );
}

// ─── Dispatcher ───────────────────────────────────────────────────────────────

function createDispatcher(compiledRoutes, runtimeOptimizer, errorHandlers = []) {
  const routesById = new Map(compiledRoutes.map((route) => [route.handlerId, route]));
  const errorRequestFactory = createRequestFactory(ERROR_REQUEST_PLAN, [], null);

  async function finalizeError(error, req, res, snapshot, release, fallbackStatus = 500) {
    try {
      if (!res.finished) {
        for (const errorHandler of errorHandlers) {
          const result = errorHandler(error, req, res);
          if (!res.finished && isPromiseLike(result)) {
            await result;
          }
          if (res.finished) {
            break;
          }
        }
      }

      if (!res.finished) {
        return encodeResponseEnvelope(buildDefaultErrorSnapshot(error, fallbackStatus));
      }

      return encodeResponseEnvelope(snapshot());
    } catch (handlerError) {
      return serializeErrorResponse(handlerError);
    } finally {
      if (req) {
        releaseRequestObject(req);
      }
      release();
    }
  }

  return async function dispatch(requestBuffer) {
    let decoded;

    try {
      decoded = decodeRequestEnvelope(requestBuffer);
    } catch (error) {
      return serializeErrorResponse(error);
    }

    if (decoded.handlerId === 0) {
      const req = errorRequestFactory(decoded);
      const { response: res, snapshot, release } = createResponseEnvelope();
      return finalizeError(
        createHttpError(404, "Route not found", "NOT_FOUND"),
        req,
        res,
        snapshot,
        release,
        404,
      );
    }

    const route = routesById.get(decoded.handlerId);
    if (!route) {
      return serializeErrorResponse(new Error(`Unknown handler id ${decoded.handlerId}`));
    }

    const cachedResponse = route.runtimeResponseCache?.encoded;
    if (cachedResponse) {
      return cachedResponse;
    }

    const req = route.requestFactory(decoded);
    const { response: res, snapshot, release } = createResponseEnvelope(route.jsonSerializer);

    try {
      const middlewareResult = route.runMiddlewares(req, res);
      if (!res.finished && isPromiseLike(middlewareResult)) {
        await middlewareResult;
      }
      if (!res.finished) {
        const handlerResult = route.compiledHandler(req, res);
        // Async handlers with no await often finish synchronously and only return
        // an already-resolved Promise. Skip awaiting when response is already done.
        if (!res.finished && isPromiseLike(handlerResult)) {
          await handlerResult;
        }
      }
    } catch (error) {
      return finalizeError(error, req, res, snapshot, release, 500);
    }

    const responseSnapshot = snapshot();
    if (!isBridgeBypassedRoute(route)) {
      runtimeOptimizer?.recordDispatch(route, req, responseSnapshot);
    }
    const encoded = encodeResponseEnvelope(responseSnapshot);
    maybePromoteRouteResponseCache(route, responseSnapshot, encoded);
    releaseRequestObject(req);
    release();
    return encoded;
  };
}

function createDispatcherSync(compiledRoutes, runtimeOptimizer, errorHandlers = []) {
  const routesById = new Map(compiledRoutes.map((route) => [route.handlerId, route]));
  const errorRequestFactory = createRequestFactory(ERROR_REQUEST_PLAN, [], null);

  function finalizeError(error, req, res, snapshot, release, fallbackStatus = 500) {
    try {
      if (!res.finished) {
        for (const errorHandler of errorHandlers) {
          const result = errorHandler(error, req, res);
          if (!res.finished && isPromiseLike(result)) {
            throw new TypeError(
              "Async error handlers are not supported on the native bun:ffi bridge.",
            );
          }
          if (res.finished) {
            break;
          }
        }
      }

      if (!res.finished) {
        return encodeResponseEnvelope(buildDefaultErrorSnapshot(error, fallbackStatus));
      }

      return encodeResponseEnvelope(snapshot());
    } catch (handlerError) {
      return serializeErrorResponse(handlerError);
    } finally {
      if (req) {
        releaseRequestObject(req);
      }
      release();
    }
  }

  return function dispatch(requestBuffer) {
    let decoded;

    try {
      decoded = decodeRequestEnvelope(requestBuffer);
    } catch (error) {
      return serializeErrorResponse(error);
    }

    if (decoded.handlerId === 0) {
      const req = errorRequestFactory(decoded);
      const { response: res, snapshot, release } = createResponseEnvelope();
      return finalizeError(
        createHttpError(404, "Route not found", "NOT_FOUND"),
        req,
        res,
        snapshot,
        release,
        404,
      );
    }

    const route = routesById.get(decoded.handlerId);
    if (!route) {
      return serializeErrorResponse(new Error(`Unknown handler id ${decoded.handlerId}`));
    }

    const cachedResponse = route.runtimeResponseCache?.encoded;
    if (cachedResponse) {
      return cachedResponse;
    }

    const req = route.requestFactory(decoded);
    const { response: res, snapshot, release } = createResponseEnvelope(route.jsonSerializer);

    try {
      const middlewareResult = route.runMiddlewares(req, res);
      if (!res.finished && isPromiseLike(middlewareResult)) {
        throw new TypeError(
          "Async middleware handlers are not supported on the native bun:ffi bridge.",
        );
      }
      if (!res.finished) {
        const handlerResult = route.compiledHandler(req, res);
        if (!res.finished && isPromiseLike(handlerResult)) {
          throw new TypeError(
            "Async route handlers are not supported on the native bun:ffi bridge.",
          );
        }
      }
    } catch (error) {
      return finalizeError(error, req, res, snapshot, release, 500);
    }

    const responseSnapshot = snapshot();
    if (!isBridgeBypassedRoute(route)) {
      runtimeOptimizer?.recordDispatch(route, req, responseSnapshot);
    }
    const encoded = encodeResponseEnvelope(responseSnapshot);
    maybePromoteRouteResponseCache(route, responseSnapshot, encoded);
    releaseRequestObject(req);
    release();
    return encoded;
  };
}

function isStaticFastPathRoute(route) {
  if (route.method !== "GET" || route.path.includes(":")) {
    return false;
  }

  if ((route.applicableMiddlewares?.length ?? 0) > 0) {
    return false;
  }

  const source = route.handlerSource ?? "";
  if (source.includes("await")) {
    return false;
  }

  const body = trimReturnAndSemicolon(extractFunctionBody(source));
  if (!body) {
    return false;
  }

  return (
    isDirectLiteralCall(body, "res.json(") ||
    isDirectLiteralCall(body, "res.send(") ||
    isDirectStatusLiteralCall(body, "json") ||
    isDirectStatusLiteralCall(body, "send")
  );
}

function isBridgeBypassedRoute(route) {
  if (isStaticFastPathRoute(route)) {
    return true;
  }

  return (
    route.dispatchKind === "specialized" &&
    route.jsonFastPath === "specialized" &&
    (route.applicableMiddlewares?.length ?? 0) === 0
  );
}

function extractFunctionBody(source) {
  const arrowIndex = source.indexOf("=>");
  if (arrowIndex >= 0) {
    const right = source.slice(arrowIndex + 2).trim();
    if (right.startsWith("{") && right.endsWith("}")) {
      return right.slice(1, -1).trim();
    }
    return right;
  }

  const blockStart = source.indexOf("{");
  const blockEnd = source.lastIndexOf("}");
  if (blockStart >= 0 && blockEnd > blockStart) {
    return source.slice(blockStart + 1, blockEnd).trim();
  }

  return source.trim();
}

function trimReturnAndSemicolon(body) {
  let value = body.trim();
  if (value.startsWith("return ")) {
    value = value.slice("return ".length).trim();
  }
  if (value.endsWith(";")) {
    value = value.slice(0, -1).trim();
  }
  return value;
}

function isDirectLiteralCall(body, prefix) {
  if (!body.startsWith(prefix) || !body.endsWith(")")) {
    return false;
  }

  const payload = body.slice(prefix.length, -1).trim();
  return looksLiteralPayload(payload);
}

function isDirectStatusLiteralCall(body, method) {
  if (!body.startsWith("res.status(") || !body.endsWith(")")) {
    return false;
  }

  const separator = `).${method}(`;
  const separatorIndex = body.indexOf(separator);
  if (separatorIndex < 0) {
    return false;
  }

  const payload = body.slice(separatorIndex + separator.length, -1).trim();
  return looksLiteralPayload(payload);
}

function looksLiteralPayload(payload) {
  if (!payload) {
    return false;
  }

  if (
    payload.startsWith("{") ||
    payload.startsWith("[") ||
    payload.startsWith('"') ||
    payload.startsWith("'") ||
    payload.startsWith("`")
  ) {
    return true;
  }

  if (/^-?\d/.test(payload)) {
    return true;
  }

  return payload === "true" || payload === "false" || payload === "null";
}

// ─── Route Registration & Compilation ─────────────────────────────────────────

function normalizeRouteRegistration(method, path, handler) {
  if (typeof handler !== "function") {
    throw new TypeError(`Handler for ${method} ${path} must be a function`);
  }

  return {
    method,
    path: normalizeRoutePath(method, path),
    handler,
  };
}

function compileMiddlewareRegistration(middleware) {
  const handlerSource = Function.prototype.toString.call(middleware.handler);

  return {
    ...middleware,
    handlerSource,
    accessPlan: analyzeRequestAccess(handlerSource),
  };
}

function createRouteResponseCache(route, applicableMiddlewares, requestPlan, optConfig) {
  if (optConfig?.cache !== true) {
    return null;
  }

  if (route.method !== "GET" || route.path.includes(":")) {
    return null;
  }

  if (applicableMiddlewares.length > 0) {
    return null;
  }

  if (!hasNoRequestAccess(requestPlan)) {
    return null;
  }

  const source = route.handlerSource ?? "";
  if (source.includes("await")) {
    return null;
  }

  if (/Date\.now|new Date|Math\.random|crypto\./.test(source)) {
    return null;
  }

  return {
    encoded: null,
    bunSnapshot: null,
    lastKey: "",
    stableHits: 0,
  };
}

function hasNoRequestAccess(plan) {
  return (
    plan.method !== true &&
    plan.path !== true &&
    plan.url !== true &&
    plan.fullParams !== true &&
    plan.fullQuery !== true &&
    plan.fullHeaders !== true &&
    plan.paramKeys.size === 0 &&
    plan.queryKeys.size === 0 &&
    plan.headerKeys.size === 0
  );
}

function maybePromoteRouteResponseCache(route, snapshot, encoded) {
  const cache = route.runtimeResponseCache;
  if (!cache || cache.encoded) {
    return;
  }

  const key = buildSnapshotCacheKey(snapshot);
  if (key === cache.lastKey) {
    cache.stableHits += 1;
  } else {
    cache.lastKey = key;
    cache.stableHits = 1;
  }

  if (cache.stableHits >= ROUTE_CACHE_PROMOTE_HITS) {
    cache.encoded = encoded;
  }
}

function buildSnapshotCacheKey(snapshot) {
  let hash = 0x811c9dc5;
  hash = fnv1aString(hash, String(snapshot.status ?? 200));

  const headers = snapshot.headers ?? Object.create(null);
  const headerNames = Object.keys(headers);
  for (const name of headerNames) {
    hash = fnv1aString(hash, name);
    hash = fnv1aString(hash, String(headers[name]));
  }

  const body = Buffer.isBuffer(snapshot.body)
    ? snapshot.body
    : snapshot.body instanceof Uint8Array
      ? snapshot.body
      : EMPTY_BUFFER;
  hash = fnv1aBytes(hash, body);

  return `${hash}:${body.length}:${headerNames.length}`;
}

function fnv1aString(seed, value) {
  let hash = seed >>> 0;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function fnv1aBytes(seed, bytes) {
  let hash = seed >>> 0;
  for (let index = 0; index < bytes.length; index += 1) {
    hash ^= bytes[index];
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function compileRouteDispatch(
  route,
  middlewares,
  errorHandlerPlans = [],
  optConfig = {},
) {
  const applicableMiddlewares = middlewares.filter((middleware) =>
    pathPrefixMatches(middleware.pathPrefix, route.path),
  );
  const requestPlan = mergeRequestAccessPlans([
    route.accessPlan,
    ...applicableMiddlewares.map((middleware) => middleware.accessPlan),
    ...errorHandlerPlans,
  ]);

  const requestFactory = createRequestFactory(
    requestPlan,
    route.paramNames,
    route.method,
  );
  const runMiddlewares = createMiddlewareRunner(applicableMiddlewares);
  const compiledHandler = route.handler;
  const jsonFastPath =
    route.accessPlan.jsonFastPath === "fallback"
      ? requestPlan.jsonFastPath
      : route.accessPlan.jsonFastPath;

  return {
    ...route,
    applicableMiddlewares,
    requestPlan,
    requestFactory,
    runMiddlewares,
    compiledHandler,
    dispatchKind: requestPlan.dispatchKind,
    jsonFastPath,
    jsonSerializer: createJsonSerializer(jsonFastPath),
    runtimeResponseCache: createRouteResponseCache(route, applicableMiddlewares, requestPlan, optConfig),
  };
}

function createMethodRegistrar(app, method) {
  return (path, handler) => {
    if (method === "ALL") {
      for (const concreteMethod of HTTP_METHODS) {
        app._routes.push(normalizeRouteRegistration(concreteMethod, path, handler));
      }
      return app;
    }

    app._routes.push(normalizeRouteRegistration(method, path, handler));
    return app;
  };
}

function normalizeListenOptions(options = {}) {
  const serverConfig = normalizeHttpServerConfig(
    options.serverConfig ?? options.httpServerConfig ?? defaultHttpServerConfig,
  );

  return {
    host: options.host ?? serverConfig.defaultHost,
    port: Number(options.port ?? 3000),
    backlog:
      options.backlog === undefined || options.backlog === null
        ? serverConfig.defaultBacklog
        : Number(options.backlog),
    opt: options.opt ?? {},
    serverConfig,
  };
}

const EMPTY_OBJECT = Object.freeze(Object.create(null));
const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

function hasAsyncHandlers(routes, middlewares, errorHandlers) {
  return (
    routes.some((route) => route?.handler?.constructor?.name === "AsyncFunction") ||
    middlewares.some((middleware) => middleware?.handler?.constructor?.name === "AsyncFunction") ||
    errorHandlers.some((handler) => handler?.constructor?.name === "AsyncFunction")
  );
}

function normalizeRuntimePath(pathname) {
  if (pathname === "/") {
    return "/";
  }

  const trimmed = String(pathname).replace(/\/+$/, "");
  return trimmed || "/";
}

function splitPathSegments(pathname) {
  if (pathname === "/") {
    return EMPTY_ARRAY;
  }

  return pathname
    .slice(1)
    .split("/")
    .filter(Boolean);
}

function buildRequestParamObject(paramValues, paramNames, plan) {
  if (!plan.fullParams && plan.paramKeys.size === 0) {
    return EMPTY_OBJECT;
  }

  const result = Object.create(null);
  for (let index = 0; index < paramValues.length; index += 1) {
    const key = paramNames[index];
    if (!key || DANGEROUS_KEYS.has(key)) {
      continue;
    }
    if (plan.fullParams || plan.paramKeys.has(key)) {
      result[key] = paramValues[index];
    }
  }
  return result;
}

function pushQueryEntry(target, key, value) {
  if (Object.hasOwn(target, key)) {
    const current = target[key];
    if (Array.isArray(current)) {
      current.push(value);
    } else {
      target[key] = [current, value];
    }
    return;
  }

  target[key] = value;
}

function buildRequestQueryObject(searchParams, plan) {
  if (!plan.fullQuery && plan.queryKeys.size === 0) {
    return EMPTY_OBJECT;
  }

  const result = Object.create(null);
  for (const [key, value] of searchParams) {
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    if (plan.fullQuery || plan.queryKeys.has(key)) {
      pushQueryEntry(result, key, value);
    }
  }

  return result;
}

function buildRequestHeaderObject(headers, plan) {
  if (!plan.fullHeaders && plan.headerKeys.size === 0) {
    return EMPTY_OBJECT;
  }

  const result = Object.create(null);
  for (const [name, value] of headers) {
    const key = String(name).toLowerCase();
    if (DANGEROUS_KEYS.has(key)) {
      continue;
    }
    if (plan.fullHeaders || plan.headerKeys.has(key)) {
      result[key] = value;
    }
  }

  return result;
}

function cloneResponseSnapshot(snapshot) {
  const headers = Object.create(null);
  for (const key in snapshot.headers) {
    headers[key] = snapshot.headers[key];
  }

  const body =
    snapshot.body instanceof Uint8Array
      ? Buffer.from(
          snapshot.body.buffer,
          snapshot.body.byteOffset,
          snapshot.body.byteLength,
        )
      : EMPTY_BUFFER;

  return {
    status: snapshot.status,
    headers,
    body,
  };
}

function createBunRequestObject(
  route,
  request,
  requestUrl,
  normalizedPath,
  paramValues,
  bodyBytes,
) {
  const plan = route?.requestPlan ?? ERROR_REQUEST_PLAN;
  const paramNames = route?.paramNames ?? EMPTY_ARRAY;
  let paramsCache;
  let queryCache;
  let headersCache;
  let bodyParsed;

  const req = Object.create(null);
  req.method = request.method;
  req.path = normalizedPath;
  req.url = requestUrl.pathname + requestUrl.search;

  Object.defineProperty(req, "params", {
    configurable: true,
    enumerable: true,
    get() {
      if (paramsCache === undefined) {
        paramsCache = buildRequestParamObject(paramValues, paramNames, plan);
      }
      return paramsCache;
    },
  });

  Object.defineProperty(req, "query", {
    configurable: true,
    enumerable: true,
    get() {
      if (queryCache === undefined) {
        queryCache = buildRequestQueryObject(requestUrl.searchParams, plan);
      }
      return queryCache;
    },
  });

  Object.defineProperty(req, "headers", {
    configurable: true,
    enumerable: true,
    get() {
      if (headersCache === undefined) {
        headersCache = buildRequestHeaderObject(request.headers, plan);
      }
      return headersCache;
    },
  });

  req.header = function header(name) {
    const value = request.headers.get(String(name));
    return value ?? undefined;
  };

  req.json = function json() {
    if (bodyParsed !== undefined) {
      return bodyParsed;
    }
    if (!bodyBytes || bodyBytes.length === 0) {
      bodyParsed = null;
      return null;
    }
    bodyParsed = JSON.parse(bodyBytes.toString("utf8"));
    return bodyParsed;
  };

  req.text = function text() {
    if (!bodyBytes || bodyBytes.length === 0) {
      return "";
    }
    return bodyBytes.toString("utf8");
  };

  req.arrayBuffer = function arrayBuffer() {
    if (!bodyBytes || bodyBytes.length === 0) {
      return new ArrayBuffer(0);
    }
    return bodyBytes.buffer.slice(
      bodyBytes.byteOffset,
      bodyBytes.byteOffset + bodyBytes.byteLength,
    );
  };

  return req;
}

function maybePromoteRouteBunSnapshotCache(route, snapshot) {
  const cache = route.runtimeResponseCache;
  if (!cache || cache.bunSnapshot) {
    return;
  }

  const key = buildSnapshotCacheKey(snapshot);
  if (key === cache.lastKey) {
    cache.stableHits += 1;
  } else {
    cache.lastKey = key;
    cache.stableHits = 1;
  }

  if (cache.stableHits >= ROUTE_CACHE_PROMOTE_HITS) {
    cache.bunSnapshot = cloneResponseSnapshot(snapshot);
  }
}

function createBunDirectDispatcher(compiledRoutes, runtimeOptimizer, errorHandlers = []) {
  async function finalizeError(error, req, res, snapshot, release, fallbackStatus = 500) {
    try {
      if (!res.finished) {
        for (const errorHandler of errorHandlers) {
          const result = errorHandler(error, req, res);
          if (!res.finished && isPromiseLike(result)) {
            await result;
          }
          if (res.finished) {
            break;
          }
        }
      }

      if (!res.finished) {
        return buildDefaultErrorSnapshot(error, fallbackStatus);
      }

      return cloneResponseSnapshot(snapshot());
    } catch {
      return buildDefaultErrorSnapshot(error, fallbackStatus);
    } finally {
      release();
    }
  }

  return async function dispatch(route, req) {
    if (!route) {
      const { response: res, snapshot, release } = createResponseEnvelope();
      return finalizeError(
        createHttpError(404, "Route not found", "NOT_FOUND"),
        req,
        res,
        snapshot,
        release,
        404,
      );
    }

    const cachedSnapshot = route.runtimeResponseCache?.bunSnapshot;
    if (cachedSnapshot) {
      return cachedSnapshot;
    }

    const { response: res, snapshot, release } = createResponseEnvelope(route.jsonSerializer);

    try {
      const middlewareResult = route.runMiddlewares(req, res);
      if (!res.finished && isPromiseLike(middlewareResult)) {
        await middlewareResult;
      }
      if (!res.finished) {
        const handlerResult = route.compiledHandler(req, res);
        if (!res.finished && isPromiseLike(handlerResult)) {
          await handlerResult;
        }
      }
    } catch (error) {
      return finalizeError(error, req, res, snapshot, release, 500);
    }

    const responseSnapshot = cloneResponseSnapshot(snapshot());
    if (!isBridgeBypassedRoute(route)) {
      runtimeOptimizer?.recordDispatch(route, req, responseSnapshot);
    }
    maybePromoteRouteBunSnapshotCache(route, responseSnapshot);
    release();
    return responseSnapshot;
  };
}

function createRouteMatcher(compiledRoutes) {
  const perMethod = new Map();

  for (const route of compiledRoutes) {
    let bucket = perMethod.get(route.methodCode);
    if (!bucket) {
      bucket = {
        exact: new Map(),
        dynamic: [],
      };
      perMethod.set(route.methodCode, bucket);
    }

    if (route.routeKind === ROUTE_KIND.EXACT) {
      bucket.exact.set(route.path, route);
      continue;
    }

    bucket.dynamic.push({
      route,
      segments: splitPathSegments(route.path),
    });
  }

  return function matchRoute(methodCode, normalizedPath) {
    const bucket = perMethod.get(methodCode);
    if (!bucket) {
      return null;
    }

    const exact = bucket.exact.get(normalizedPath);
    if (exact) {
      return {
        route: exact,
        paramValues: EMPTY_ARRAY,
      };
    }

    const requestSegments = splitPathSegments(normalizedPath);
    for (const candidate of bucket.dynamic) {
      if (candidate.segments.length !== requestSegments.length) {
        continue;
      }

      const paramValues = [];
      let matches = true;
      for (let index = 0; index < candidate.segments.length; index += 1) {
        const routeSegment = candidate.segments[index];
        const requestSegment = requestSegments[index];
        if (routeSegment.startsWith(":")) {
          paramValues.push(requestSegment);
          continue;
        }

        if (routeSegment !== requestSegment) {
          matches = false;
          break;
        }
      }

      if (matches) {
        return {
          route: candidate.route,
          paramValues,
        };
      }
    }

    return null;
  };
}

async function startBunServerBridge(
  compiledRoutes,
  runtimeOptimizer,
  errorHandlers,
  normalizedOptions,
) {
  const matchRoute = createRouteMatcher(compiledRoutes);
  const dispatchDirect = createBunDirectDispatcher(
    compiledRoutes,
    runtimeOptimizer,
    errorHandlers,
  );
  const fetchHandler = async (request) => {
    try {
      const requestUrl = new URL(request.url);
      const methodCode = METHOD_CODES[request.method] ?? 0;
      const normalizedPath = normalizeRuntimePath(requestUrl.pathname);
      const matched = matchRoute(methodCode, normalizedPath);
      const bodyBytes =
        request.method === "GET" || request.method === "HEAD"
          ? EMPTY_BUFFER
          : Buffer.from(await request.arrayBuffer());
      const route = matched?.route ?? null;
      const req = createBunRequestObject(
        route,
        request,
        requestUrl,
        normalizedPath,
        matched?.paramValues ?? EMPTY_ARRAY,
        bodyBytes,
      );
      const snapshot = await dispatchDirect(route, req);
      return new Response(snapshot.body, {
        status: snapshot.status,
        headers: snapshot.headers,
      });
    } catch {
      return new Response('{"error":"Internal Server Error"}', {
        status: 500,
        headers: {
          "content-type": "application/json; charset=utf-8",
        },
      });
    }
  };

  let server;
  let lastBindError;
  const requestedPort = normalizedOptions.port;
  const maxPortAttempts = requestedPort === 0 ? 16 : 1;

  for (let attempt = 0; attempt < maxPortAttempts; attempt += 1) {
    const candidatePort =
      requestedPort === 0
        ? 30000 + Math.floor(Math.random() * 20000)
        : requestedPort;
    try {
      server = Bun.serve({
        hostname: normalizedOptions.host,
        port: candidatePort,
        fetch: fetchHandler,
      });
      break;
    } catch (error) {
      lastBindError = error;
      if (requestedPort !== 0) {
        throw error;
      }
    }
  }

  if (!server) {
    throw lastBindError ?? new Error("Failed to bind Bun server");
  }

  ACTIVE_NATIVE_SERVERS.add(server);
  const host = server.hostname;
  const port = Number(server.port);
  const url =
    typeof server.url === "string"
      ? server.url
      : server.url?.toString?.() ?? `http://${host}:${port}`;

  return {
    host,
    port,
    url,
    _handle: server,
    optimizations: {
      snapshot() {
        return runtimeOptimizer.snapshot();
      },
      summary() {
        return runtimeOptimizer.summary();
      },
    },
    close() {
      ACTIVE_NATIVE_SERVERS.delete(server);
      server.stop(true);
    },
  };
}

// ─── Application Factory ─────────────────────────────────────────────────────

export function createApp() {
  let nextHandlerId = 1;

  const app = {
    _routes: [],
    _middlewares: [],
    _errorHandlers: [],

    use(pathOrMiddleware, maybeMiddleware) {
      let pathPrefix = "/";
      let handler = pathOrMiddleware;

      if (typeof pathOrMiddleware === "string") {
        pathPrefix = normalizePathPrefix(pathOrMiddleware);
        handler = maybeMiddleware;
      }

      if (typeof handler !== "function") {
        throw new TypeError("Middleware must be a function");
      }

      this._middlewares.push({ pathPrefix, handler });
      return this;
    },

    onError(handler) {
      if (typeof handler !== "function") {
        throw new TypeError("Error handler must be a function");
      }
      this._errorHandlers.push(handler);
      return this;
    },

    error(handler) {
      return this.onError(handler);
    },

    get: undefined,
    post: undefined,
    put: undefined,
    delete: undefined,
    patch: undefined,
    options: undefined,
    all: undefined,

    async listen(options = {}) {
      const normalizedOptions = normalizeListenOptions(options);
      const compiledMiddlewares = this._middlewares.map(compileMiddlewareRegistration);
      const errorHandlerPlans = this._errorHandlers.map((handler) =>
        analyzeRequestAccess(Function.prototype.toString.call(handler)),
      );

      const routes = this._routes.map((route) => {
        const handlerSource = Function.prototype.toString.call(route.handler);

        return {
        ...route,
        handlerId: nextHandlerId++,
        handlerSource,
        accessPlan: analyzeRequestAccess(handlerSource),
        ...compileRouteShape(route.method, route.path),
        };
      });
      const compiledRoutes = routes.map((route) =>
        compileRouteDispatch(
          route,
          compiledMiddlewares,
          errorHandlerPlans,
          normalizedOptions.opt,
        ),
      );

      const manifest = {
        version: 1,
        serverConfig: normalizedOptions.serverConfig,
        middlewares: compiledMiddlewares.map((middleware) => ({
          pathPrefix: middleware.pathPrefix,
        })),
        routes: compiledRoutes.map((route) => ({
          jsDispatch: !isBridgeBypassedRoute(route),
          cacheCandidate: !isBridgeBypassedRoute(route) && route.runtimeResponseCache !== null,
          method: route.method,
          methodCode: route.methodCode,
          path: route.path,
          routeKind: route.routeKind,
          handlerId: route.handlerId,
          handlerSource: route.handlerSource,
          paramNames: route.paramNames,
          segmentCount: route.segmentCount,
          headerKeys: [...route.requestPlan.headerKeys],
          fullHeaders: route.requestPlan.fullHeaders,
          needsPath: route.requestPlan.path,
          needsUrl: route.requestPlan.url,
          needsQuery:
            route.requestPlan.fullQuery ||
            route.requestPlan.queryKeys.size > 0,
        })),
      };

      const runtimeOptimizer = createRuntimeOptimizer(
        compiledRoutes,
        compiledMiddlewares,
        normalizedOptions.opt,
      );
      const dispatcher = createDispatcher(
        compiledRoutes,
        runtimeOptimizer,
        this._errorHandlers,
      );
      const native = loadNativeModule();
      const handle = native.startServer(JSON.stringify(manifest), dispatcher, {
        host: normalizedOptions.host,
        port: normalizedOptions.port,
        backlog: normalizedOptions.backlog,
      });
      ACTIVE_NATIVE_SERVERS.add(handle);
      retainNativeProcessLifetime();

      return {
        host: handle.host,
        port: handle.port,
        url: handle.url,
        _handle: handle,
        optimizations: {
          snapshot() {
            return runtimeOptimizer.snapshot();
          },
          summary() {
            return runtimeOptimizer.summary();
          },
        },
        close() {
          ACTIVE_NATIVE_SERVERS.delete(handle);
          const result = handle.close();
          releaseNativeProcessLifetime();
          return result;
        },
      };
    },
  };

  app.get = createMethodRegistrar(app, "GET");
  app.post = createMethodRegistrar(app, "POST");
  app.put = createMethodRegistrar(app, "PUT");
  app.delete = createMethodRegistrar(app, "DELETE");
  app.patch = createMethodRegistrar(app, "PATCH");
  app.options = createMethodRegistrar(app, "OPTIONS");
  app.all = createMethodRegistrar(app, "ALL");

  return app;
}

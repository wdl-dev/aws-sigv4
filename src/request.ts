// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { AUTHORIZATION_HEADER, HOST_HEADER } from "./constants.js";
import type { SigV4RequestInit, SignedAwsRequest } from "./types.js";
import { hasDotPathSegment, parseRequestUrl, type ParsedRequestUrl } from "./url.js";

const HTTP_METHOD_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]);

interface RequestInputSnapshot {
  url: string;
  method: string;
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
  bodyUsed: boolean;
  init: RequestInit;
}

export interface ResolvedClientRequest {
  requestUrl: ParsedRequestUrl;
  init: SigV4RequestInit;
  method: string;
  headers: Headers;
  body: BodyInit | null | undefined;
  signal: AbortSignal | undefined;
}

export interface ResolvedClientFetchRequest extends ResolvedClientRequest {
  redirectPolicy: RequestRedirect;
}

interface ClientRequestResolution {
  request: ResolvedClientRequest;
  inheritedRedirect: RequestRedirect | undefined;
  explicitRedirect: unknown;
}

export function resolveClientSignRequest(
  input: Request | string | URL,
  init?: SigV4RequestInit
): ResolvedClientRequest {
  return resolveClientRequest(input, init).request;
}

export function resolveClientFetchRequest(
  input: Request | string | URL,
  init?: SigV4RequestInit
): ResolvedClientFetchRequest {
  const { request, inheritedRedirect, explicitRedirect } = resolveClientRequest(input, init);
  const redirectPolicy = safeFetchRedirect(inheritedRedirect, explicitRedirect);
  request.init.redirect = "manual";
  return { ...request, redirectPolicy };
}

function resolveClientRequest(input: Request | string | URL, init?: SigV4RequestInit): ClientRequestResolution {
  const inputSnapshot = input instanceof Request ? snapshotRequestInput(input) : undefined;
  const requestUrl = parseRequestUrl(inputSnapshot?.url ?? (input as string | URL));
  const initSnapshot = snapshotRequestInit(init);
  const requestInit = inputSnapshot ? mergeDefinedRequestInit(inputSnapshot.init, initSnapshot) : initSnapshot;
  const signal = requestInit.signal ?? undefined;
  signal?.throwIfAborted();
  rejectNoCorsMode(requestInit.mode);

  const headers =
    inputSnapshot === undefined
      ? new Headers(requestInit.headers)
      : mergeHeaders(inputSnapshot.headers, requestInit.headers);
  let body = requestInit.body;
  let method = requestInit.method;
  if (inputSnapshot !== undefined) {
    rejectUsedRequestBody(inputSnapshot.bodyUsed, body);
    if ((body === undefined || body === null) && inputSnapshot.body) {
      body = inputSnapshot.body;
    }
    if (method === undefined) {
      method = inputSnapshot.method;
    }
  }
  const normalizedMethod = normalizeMethod(method === undefined ? defaultMethod(body) : method);
  rejectFetchForbiddenMethod(normalizedMethod);
  rejectRequestBodyForGetHead(normalizedMethod, body);
  requestInit.method = normalizedMethod;
  requestInit.headers = headers;
  if (body === undefined) {
    delete requestInit.body;
  } else {
    requestInit.body = body;
  }

  return {
    request: {
      requestUrl,
      init: requestInit,
      method: normalizedMethod,
      headers,
      body,
      signal,
    },
    inheritedRedirect: inputSnapshot?.init.redirect,
    explicitRedirect: initSnapshot.redirect,
  };
}

function mergeHeaders(base: HeadersInit, override: HeadersInit | undefined): Headers {
  const headers = new Headers(base);
  if (override !== undefined) {
    new Headers(override).forEach((value, name) => {
      headers.set(name, value);
    });
  }
  return headers;
}

function mergeDefinedRequestInit(base: RequestInit, override: SigV4RequestInit): SigV4RequestInit {
  const out: SigV4RequestInit = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value !== undefined) {
      (out as Record<string, unknown>)[key] = value;
    }
  }
  return out;
}

function snapshotRequestInit(value: unknown): SigV4RequestInit {
  if (value !== undefined && value !== null && typeof value !== "object") {
    throw new TypeError("init must be an object");
  }
  if (value === undefined || value === null) {
    return {};
  }
  return { ...(value as SigV4RequestInit) };
}

export function rejectEmptyHeader(headers: Headers, name: string): void {
  if (headers.get(name) === "") {
    throw new TypeError(`${name} must not be empty`);
  }
}

function snapshotRequestInput(request: Request): RequestInputSnapshot {
  const url = request.url;
  const method = request.method;
  const headers = new Headers(request.headers);
  const body = request.body;
  const bodyUsed = request.bodyUsed;
  const init: RequestInit = {
    cache: request.cache,
    credentials: request.credentials,
    integrity: request.integrity,
    keepalive: request.keepalive,
    mode: request.mode,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    signal: request.signal,
    window: null,
  };
  const duplex = (request as Request & { duplex?: unknown }).duplex;
  if (duplex === "half") {
    return {
      url,
      method,
      headers,
      body,
      bodyUsed,
      init: { ...init, duplex } as RequestInit & { duplex: "half" },
    };
  }
  return { url, method, headers, body, bodyUsed, init };
}

function rejectUsedRequestBody(bodyUsed: boolean, override: BodyInit | null | undefined): void {
  if ((override === undefined || override === null) && bodyUsed) {
    throw new TypeError("Request body has already been used");
  }
}

export function defaultMethod(body: BodyInit | null | undefined): string {
  return hasRequestBody(body) ? "POST" : "GET";
}

export function normalizeMethod(method: unknown): string {
  if (typeof method !== "string" || !HTTP_METHOD_RE.test(method)) {
    throw new TypeError("method must be a valid HTTP token");
  }
  return method.toUpperCase();
}

function rejectFetchForbiddenMethod(method: string): void {
  if (method === "CONNECT" || method === "TRACE" || method === "TRACK") {
    throw new TypeError(`SigV4Client cannot use Fetch-forbidden method ${method}`);
  }
}

export function isIdempotentMethod(method: string): boolean {
  return IDEMPOTENT_METHODS.has(method);
}

function rejectRequestBodyForGetHead(method: string, body: BodyInit | null | undefined): void {
  if ((method === "GET" || method === "HEAD") && hasRequestBody(body)) {
    throw new TypeError("GET and HEAD requests with a body require signAwsRequest");
  }
}

function hasRequestBody(body: BodyInit | null | undefined): boolean {
  return body !== undefined && body !== null;
}

export function assertParsedRequestCanRepresentSignedUrl(pathname: string, service: string): void {
  if (hasDotPathSegment(pathname)) {
    throw new TypeError(`SigV4Client cannot represent ${service} URLs with dot segments; use signAwsRequest`);
  }
}

export function requestInitForSignedRequest(base: RequestInit, signed: SignedAwsRequest): RequestInit {
  const out: RequestInit = {
    ...base,
    method: signed.method,
    headers: signed.headers,
  };
  if (signed.body !== undefined) {
    out.body = signed.body;
  }
  return out;
}

export function createSignedRequest(url: string, init: RequestInit, expectedHeaders: Headers): Request {
  let request: Request;
  try {
    request = new Request(url, init);
  } catch (err) {
    const duplex = (init as RequestInit & { duplex?: unknown }).duplex;
    if (!(err instanceof TypeError) || !(init.body instanceof ReadableStream) || duplex !== undefined) {
      throw err;
    }
    request = new Request(url, {
      ...init,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
  }
  assertSignedRequestHeadersPreserved(expectedHeaders, request.headers);
  return request;
}

function rejectNoCorsMode(mode: RequestMode | undefined): void {
  if (mode === "no-cors") {
    throw new TypeError('SigV4Client cannot sign requests with mode "no-cors" because required headers may be removed');
  }
}

export function validateRequestBeforeTransport(request: Request): AbortSignal {
  try {
    request.signal.throwIfAborted();
    rejectNoCorsMode(request.mode);
    if (request.redirect !== "manual") {
      throw new TypeError('SigV4Client.fetch signed Request must use redirect: "manual"');
    }
    return request.signal;
  } catch (err) {
    cancelRequestBody(request, err);
    throw err;
  }
}

export function isRedirectResponse(response: Response): boolean {
  return (
    response.type === "opaqueredirect" ||
    response.redirected ||
    response.status === 301 ||
    response.status === 302 ||
    response.status === 303 ||
    response.status === 307 ||
    response.status === 308
  );
}

export function assertSignedRequestHeadersPreserved(expected: Headers, actual: Headers): void {
  const authorization = expected.get(AUTHORIZATION_HEADER);
  if (authorization === null || actual.get(AUTHORIZATION_HEADER) !== authorization) {
    throw new TypeError("runtime removed or rewrote the authorization header after signing");
  }
  const signedHeaders = /(?:^|,\s*)SignedHeaders=([^,\s]+)/u.exec(authorization)?.[1];
  if (!signedHeaders) {
    throw new Error("generated SigV4 authorization is missing SignedHeaders");
  }
  for (const name of signedHeaders.split(";")) {
    // Browser Fetch implementations own Host, but derive it from the same URL
    // that was signed. Every other signed header must survive Request guards.
    if (name === HOST_HEADER) {
      continue;
    }
    if (actual.get(name) !== expected.get(name)) {
      throw new TypeError(`runtime removed or rewrote the signed ${name} header`);
    }
  }
}

export function bindFetch(fetchFn: (request: Request) => Promise<Response>): (request: Request) => Promise<Response> {
  return Object.is(fetchFn, globalThis.fetch) ? fetchFn.bind(globalThis) : fetchFn;
}

function safeFetchRedirect(inherited: RequestRedirect | undefined, explicit: unknown): RequestRedirect {
  if (explicit !== undefined) {
    if (explicit === "follow") {
      throw new TypeError('SigV4Client.fetch does not allow redirect: "follow"; redirected requests must be re-signed');
    }
    if (explicit !== "error" && explicit !== "manual") {
      throw new TypeError('redirect must be "error" or "manual"');
    }
    return explicit;
  }
  return inherited === "manual" ? "manual" : "error";
}

function cancelRequestBody(request: Request, reason: unknown): void {
  try {
    const cancellation = request.body?.cancel(reason);
    if (cancellation !== undefined) {
      void cancellation.catch(() => undefined);
    }
  } catch {
    // Best-effort release when a signed request is rejected before transport.
  }
}

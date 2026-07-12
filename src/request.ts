// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { AUTHORIZATION_HEADER, HOST_HEADER, HTTP_METHOD_RE, IDEMPOTENT_METHODS } from "./constants.js";
import type { SigV4RequestInit, SignedAwsRequest } from "./types.js";
import { hasDotPathSegment, parseRequestUrl } from "./url.js";

export interface RequestInputSnapshot {
  url: string;
  method: string;
  headers: Headers;
  body: ReadableStream<Uint8Array> | null;
  bodyUsed: boolean;
  signal: AbortSignal;
  init: RequestInit;
}

export function mergeHeaders(base: HeadersInit, override: HeadersInit | undefined): Headers {
  const headers = new Headers(base);
  if (override !== undefined) {
    new Headers(override).forEach((value, name) => {
      headers.set(name, value);
    });
  }
  return headers;
}

export function mergeDefinedRequestInit(base: RequestInit, override: SigV4RequestInit): SigV4RequestInit {
  const out: SigV4RequestInit = { ...base };
  for (const [key, value] of Object.entries(override)) {
    if (value !== undefined) {
      (out as Record<string, unknown>)[key] = value;
    }
  }
  return out;
}

export function snapshotRequestInit(value: unknown): SigV4RequestInit {
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

export function snapshotRequestInput(request: Request): RequestInputSnapshot {
  const url = request.url;
  const method = request.method;
  const headers = new Headers(request.headers);
  const body = request.body;
  const bodyUsed = request.bodyUsed;
  const signal = request.signal;
  const init: RequestInit = {
    cache: request.cache,
    credentials: request.credentials,
    integrity: request.integrity,
    keepalive: request.keepalive,
    mode: request.mode,
    redirect: request.redirect,
    referrer: request.referrer,
    referrerPolicy: request.referrerPolicy,
    signal,
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
      signal,
      init: { ...init, duplex } as RequestInit & { duplex: "half" },
    };
  }
  return { url, method, headers, body, bodyUsed, signal, init };
}

export function requestBodyForInput(
  input: RequestInputSnapshot | undefined,
  init: RequestInit
): BodyInit | null | undefined {
  if (init.body !== undefined && init.body !== null) {
    return init.body;
  }
  return input?.body;
}

export function rejectUsedRequestBody(bodyUsed: boolean, override: BodyInit | null | undefined): void {
  if ((override === undefined || override === null) && bodyUsed) {
    throw new TypeError("Request body has already been used");
  }
}

export function methodForRequest(input: RequestInputSnapshot | undefined, init: RequestInit): string {
  if (init.method !== undefined) {
    return normalizeMethod(init.method);
  }
  if (input !== undefined) {
    return normalizeMethod(input.method);
  }
  return defaultMethod(init.body);
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

export function rejectFetchForbiddenMethod(method: string): void {
  if (method === "CONNECT" || method === "TRACE" || method === "TRACK") {
    throw new TypeError(`SigV4Client cannot use Fetch-forbidden method ${method}`);
  }
}

export function isIdempotentMethod(method: string): boolean {
  return IDEMPOTENT_METHODS.has(method);
}

export function rejectRequestBodyForGetHead(method: string, body: BodyInit | null | undefined): void {
  if ((method === "GET" || method === "HEAD") && hasRequestBody(body)) {
    throw new TypeError("GET and HEAD requests with a body require signAwsRequest");
  }
}

export function hasRequestBody(body: BodyInit | null | undefined): boolean {
  return body !== undefined && body !== null;
}

export function assertRequestCanRepresentSignedUrl(url: string | URL, service: string): void {
  assertParsedRequestCanRepresentSignedUrl(parseRequestUrl(url).pathname, service);
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

export function rejectNoCorsMode(mode: RequestMode | undefined): void {
  if (mode === "no-cors") {
    throw new TypeError('SigV4Client cannot sign requests with mode "no-cors" because required headers may be removed');
  }
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

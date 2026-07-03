// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { HTTP_METHOD_RE, IDEMPOTENT_METHODS } from "./constants.js";
import type { SigV4RequestInit, SignedAwsRequest } from "./types.js";
import { hasDotPathSegment, parseRequestUrl } from "./url.js";

export function mergeHeaders(base: HeadersInit, override: HeadersInit | undefined): Headers {
  const headers = new Headers(base);
  if (override) {
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

export function rejectEmptyHeader(headers: Headers, name: string): void {
  if (headers.get(name) === "") {
    throw new TypeError(`${name} must not be empty`);
  }
}

export function requestInitFromRequest(request: Request): RequestInit {
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
    return { ...init, duplex } as RequestInit & { duplex: "half" };
  }
  return init;
}

export function requestBodyForInput(input: Request | string | URL, init: RequestInit): BodyInit | null | undefined {
  if (init.body !== undefined) {
    return init.body;
  }
  return input instanceof Request ? input.body : undefined;
}

export function methodForRequest(input: Request | string | URL, init: RequestInit): string {
  if (init.method !== undefined) {
    return normalizeMethod(init.method);
  }
  if (input instanceof Request) {
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

export function bindFetch(fetchFn: typeof fetch): typeof fetch {
  return Object.is(fetchFn, globalThis.fetch) ? fetchFn.bind(globalThis) : fetchFn;
}

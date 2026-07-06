// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { prepareHashedBody, shouldHashPayload } from "./body.js";
import { AMZ_CONTENT_SHA256_HEADER } from "./constants.js";
import { sha256Hex } from "./crypto.js";
import { signerOverwrittenHeaderNames, validateSignedHeaderValues } from "./headers.js";
import {
  normalizeClientSigningOptions,
  normalizeUnsignableHeaders,
  optionalBoolean,
  requireNonNegativeFiniteNumber,
  requireNonNegativeInteger,
  requireSigningCache,
  resolveUnsignedPayload,
  validateCredentialOptions,
} from "./options.js";
import {
  assertParsedRequestCanRepresentSignedUrl,
  assertRequestCanRepresentSignedUrl,
  bindFetch,
  defaultMethod,
  isIdempotentMethod,
  mergeDefinedRequestInit,
  mergeHeaders,
  methodForRequest,
  rejectEmptyHeader,
  rejectRequestBodyForGetHead,
  requestBodyForInput,
  requestInitForSignedRequest,
  requestInitFromRequest,
  normalizeMethod,
} from "./request.js";
import { abortReason, cancelResponseBody, isAbortError, sleep } from "./retry.js";
import { signAwsRequestInternal } from "./signer.js";
import type { SigV4ClientOptions, SigV4RequestInit } from "./types.js";
import { parseRequestUrl } from "./url.js";

interface ReusableRequestOptions {
  defaultService: string;
  defaultUnsignedPayload: boolean | undefined;
  defaultSignAllHeaders: boolean | undefined;
  defaultUnsignableHeaders: readonly string[] | undefined;
  hasClientSessionToken: boolean;
  replayBody: boolean;
}

/**
 * Small SigV4 client with `sign()` and `fetch()` helpers.
 */
export class SigV4Client {
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private secretAccessKeyHash: Promise<string> | undefined;
  private readonly sessionToken: string | undefined;
  private readonly service: string;
  private readonly region: string;
  private readonly cache: Map<string, ArrayBuffer>;
  private readonly retries: number;
  private readonly initialRetryDelayMs: number;
  private readonly maxRetryDelayMs: number;
  private readonly unsignedPayload: boolean | undefined;
  private readonly signAllHeaders: boolean | undefined;
  private readonly unsignableHeaders: string[] | undefined;
  private readonly doubleUrlEncode: boolean | undefined;
  private readonly fetchFn: typeof fetch;

  constructor(options: SigV4ClientOptions) {
    validateCredentialOptions(options, "SigV4Client options are required");
    this.accessKeyId = options.accessKeyId;
    this.secretAccessKey = options.secretAccessKey;
    this.sessionToken = options.sessionToken;
    this.service = options.service;
    this.region = options.region;
    this.cache = requireSigningCache(options.cache, "cache") ?? new Map<string, ArrayBuffer>();
    this.retries = requireNonNegativeInteger(options.retries ?? 0, "retries");
    this.initialRetryDelayMs = requireNonNegativeFiniteNumber(options.initialRetryDelayMs ?? 50, "initialRetryDelayMs");
    this.maxRetryDelayMs = requireNonNegativeFiniteNumber(options.maxRetryDelayMs ?? 5000, "maxRetryDelayMs");
    this.unsignedPayload = optionalBoolean(options.unsignedPayload, "unsignedPayload");
    this.signAllHeaders = optionalBoolean(options.signAllHeaders, "signAllHeaders");
    this.unsignableHeaders = normalizeUnsignableHeaders(options.unsignableHeaders, "unsignableHeaders");
    this.doubleUrlEncode = optionalBoolean(options.doubleUrlEncode, "doubleUrlEncode");
    const fetchFn = options.fetch === undefined ? globalThis.fetch : options.fetch;
    if (typeof fetchFn !== "function") {
      throw new TypeError(options.fetch === undefined ? "fetch is not available" : "fetch must be a function");
    }
    this.fetchFn = bindFetch(fetchFn);
  }

  async sign(input: Request | string | URL, init: SigV4RequestInit = {}): Promise<Request> {
    const requestInit: SigV4RequestInit =
      input instanceof Request ? mergeDefinedRequestInit(requestInitFromRequest(input), init) : { ...init };
    const signingOptions = normalizeClientSigningOptions(requestInit.signing);
    delete requestInit.signing;

    let url: string | URL;
    let method = requestInit.method;
    let headers = requestInit.headers;
    let body = requestInit.body;

    if (input instanceof Request) {
      url = input.url;
      if (method === undefined) {
        method = input.method;
      }
      headers = mergeHeaders(input.headers, headers);
      if (body === undefined && input.body) {
        body = input.clone().body;
      }
    } else {
      url = input;
    }
    const normalizedMethod = normalizeMethod(method === undefined ? defaultMethod(body) : method);
    rejectRequestBodyForGetHead(normalizedMethod, body);
    const service = signingOptions.service ?? this.service;
    const requestUrl = parseRequestUrl(url);
    assertParsedRequestCanRepresentSignedUrl(requestUrl.pathname, service);

    const signed = await signAwsRequestInternal(
      {
        accessKeyId: this.accessKeyId,
        secretAccessKey: this.secretAccessKey,
        sessionToken: this.sessionToken,
        service,
        region: signingOptions.region ?? this.region,
        cache: this.cache,
        unsignedPayload: signingOptions.unsignedPayload ?? this.unsignedPayload,
        signAllHeaders: signingOptions.signAllHeaders ?? this.signAllHeaders,
        unsignableHeaders: signingOptions.unsignableHeaders ?? this.unsignableHeaders,
        doubleUrlEncode: signingOptions.doubleUrlEncode ?? this.doubleUrlEncode,
        signingDate: signingOptions.signingDate,
        method: normalizedMethod,
        url,
        headers,
        body,
      },
      await this.getSecretAccessKeyHash(),
      requestUrl
    );

    assertRequestCanRepresentSignedUrl(signed.url, service);
    const signedInit = requestInitForSignedRequest(requestInit, signed);
    try {
      return new Request(signed.url, signedInit);
    } catch (err) {
      if (err instanceof TypeError) {
        return new Request(signed.url, {
          ...signedInit,
          duplex: "half",
        } as RequestInit & { duplex: "half" });
      }
      throw err;
    }
  }

  async fetch(input: Request | string | URL, init: SigV4RequestInit = {}): Promise<Response> {
    const requestInit = {
      ...init,
      signing: normalizeClientSigningOptions(init.signing),
    };
    const method = methodForRequest(input, requestInit);
    rejectRequestBodyForGetHead(method, requestBodyForInput(input, requestInit));
    const service = requestInit.signing.service ?? this.service;
    assertRequestCanRepresentSignedUrl(input instanceof Request ? input.url : input, service);
    const replayBody = this.retries > 0 && isIdempotentMethod(method);
    const retryInit = await reusableRequestInitForInput(input, requestInit, {
      defaultService: this.service,
      defaultUnsignedPayload: this.unsignedPayload,
      defaultSignAllHeaders: this.signAllHeaders,
      defaultUnsignableHeaders: this.unsignableHeaders,
      hasClientSessionToken: this.sessionToken !== undefined,
      replayBody,
    });
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      const fetchFn = this.fetchFn;
      const request = await this.sign(input, retryInit);
      let response;
      try {
        response = await fetchFn(request);
      } catch (err) {
        if (attempt === this.retries || !isIdempotentMethod(request.method) || isAbortError(err, request)) {
          throw err;
        }
        await sleep(Math.random() * this.retryDelayMs(attempt), request.signal);
        continue;
      }
      const retryableResponse =
        isIdempotentMethod(request.method) && (response.status >= 500 || response.status === 429);
      if (attempt === this.retries || !retryableResponse) {
        return response;
      }
      await cancelResponseBody(response);
      if (request.signal.aborted) {
        throw abortReason(request.signal);
      }
      await sleep(Math.random() * this.retryDelayMs(attempt), request.signal);
    }
    throw new Error("unreachable retry loop exit");
  }

  private getSecretAccessKeyHash(): Promise<string> {
    if (this.secretAccessKeyHash !== undefined) {
      return this.secretAccessKeyHash;
    }
    const hash = sha256Hex(this.secretAccessKey).catch((err: unknown) => {
      if (this.secretAccessKeyHash === hash) {
        this.secretAccessKeyHash = undefined;
      }
      throw err;
    });
    this.secretAccessKeyHash = hash;
    return hash;
  }

  private retryDelayMs(attempt: number): number {
    return Math.min(this.maxRetryDelayMs, this.initialRetryDelayMs * 2 ** attempt);
  }
}

async function reusableRequestInitForInput(
  input: Request | string | URL,
  init: SigV4RequestInit,
  options: ReusableRequestOptions
): Promise<SigV4RequestInit> {
  if (!(input instanceof Request)) {
    return reusableRequestInit(init, options);
  }
  const inputInit: SigV4RequestInit = {
    ...init,
    method: init.method ?? input.method,
    headers: mergeHeaders(input.headers, init.headers),
  };
  if (init.body === undefined && input.body) {
    inputInit.body = input.clone().body;
  }
  return reusableRequestInit(inputInit, options);
}

async function reusableRequestInit(init: SigV4RequestInit, options: ReusableRequestOptions): Promise<SigV4RequestInit> {
  const headers = new Headers(init.headers || {});
  rejectEmptyHeader(headers, AMZ_CONTENT_SHA256_HEADER);
  const service = init.signing?.service ?? options.defaultService;
  const unsignedPayload = resolveUnsignedPayload(
    init.signing?.unsignedPayload ?? options.defaultUnsignedPayload,
    service
  );
  const unsignableHeaders = (init.signing?.unsignableHeaders ?? options.defaultUnsignableHeaders) as
    readonly string[] | undefined;
  validateSignedHeaderValues(headers, {
    signAllHeaders: init.signing?.signAllHeaders ?? options.defaultSignAllHeaders,
    unsignableHeaders,
    overwrittenHeaderNames: signerOverwrittenHeaderNames(options.hasClientSessionToken),
  });
  const materializeBody = options.replayBody && (init.body instanceof FormData || init.body instanceof ReadableStream);
  const hashPayload = shouldHashPayload(init.body, headers, unsignedPayload);
  if (!materializeBody && !hashPayload) {
    return init;
  }
  const body = await prepareHashedBody(init.body, headers, unsignedPayload, materializeBody);
  const out: SigV4RequestInit = {
    ...init,
    headers,
  };
  if (body.body !== undefined) {
    out.body = body.body;
  }
  return out;
}

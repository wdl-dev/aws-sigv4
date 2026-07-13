// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { prepareSigningBody, type PreparedBody } from "./body.js";
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
  resolveDoubleUrlEncode,
  resolveUnsignedPayload,
  validateCredentialOptions,
} from "./options.js";
import {
  assertParsedRequestCanRepresentSignedUrl,
  bindFetch,
  createSignedRequest,
  isIdempotentMethod,
  isRedirectResponse,
  rejectEmptyHeader,
  requestInitForSignedRequest,
  resolveClientFetchRequest,
  resolveClientSignRequest,
  validateRequestBeforeTransport,
  type ResolvedClientFetchRequest,
  type ResolvedClientRequest,
} from "./request.js";
import { cancelResponseBody, isAbortError, sleep } from "./retry.js";
import { signAwsRequestInternal } from "./signer.js";
import type { SigV4ClientOptions, SigV4RequestInit, SigningKeyCache } from "./types.js";

interface ResolvedSigningOptions {
  service: string;
  region: string;
  unsignedPayload: boolean;
  signAllHeaders: boolean | undefined;
  unsignableHeaders: readonly string[] | undefined;
  doubleUrlEncode: boolean;
  signingDate: string | Date | undefined;
}

interface PreparedFetchRequest {
  request: ResolvedClientFetchRequest;
  body: PreparedBody;
}

const MAX_RETRY_DELAY_MS = 2_147_483_647;

/**
 * Small SigV4 client with `sign()` and `fetch()` helpers.
 */
export class SigV4Client {
  readonly #accessKeyId: string;
  readonly #secretAccessKey: string;
  #secretAccessKeyHash: Promise<string> | undefined;
  readonly #sessionToken: string | undefined;
  readonly #service: string;
  readonly #region: string;
  readonly #cache: SigningKeyCache;
  readonly #retries: number;
  readonly #initialRetryDelayMs: number;
  readonly #maxRetryDelayMs: number;
  readonly #unsignedPayload: boolean | undefined;
  readonly #signAllHeaders: boolean | undefined;
  readonly #unsignableHeaders: string[] | undefined;
  readonly #doubleUrlEncode: boolean | undefined;
  readonly #fetchFn: (request: Request) => Promise<Response>;

  constructor(options: SigV4ClientOptions) {
    validateCredentialOptions(options, "SigV4Client options are required");
    this.#accessKeyId = options.accessKeyId;
    this.#secretAccessKey = options.secretAccessKey;
    this.#sessionToken = options.sessionToken;
    this.#service = options.service;
    this.#region = options.region;
    this.#cache = requireSigningCache(options.cache, "cache") ?? new Map<string, ArrayBuffer>();
    this.#retries = requireNonNegativeInteger(options.retries === undefined ? 0 : options.retries, "retries");
    this.#initialRetryDelayMs = requireNonNegativeFiniteNumber(
      options.initialRetryDelayMs === undefined ? 50 : options.initialRetryDelayMs,
      "initialRetryDelayMs"
    );
    this.#maxRetryDelayMs = requireNonNegativeFiniteNumber(
      options.maxRetryDelayMs === undefined ? 5000 : options.maxRetryDelayMs,
      "maxRetryDelayMs"
    );
    this.#unsignedPayload = optionalBoolean(options.unsignedPayload, "unsignedPayload");
    this.#signAllHeaders = optionalBoolean(options.signAllHeaders, "signAllHeaders");
    this.#unsignableHeaders = normalizeUnsignableHeaders(options.unsignableHeaders, "unsignableHeaders");
    this.#doubleUrlEncode = optionalBoolean(options.doubleUrlEncode, "doubleUrlEncode");
    const fetchFn = options.fetch === undefined ? globalThis.fetch : options.fetch;
    if (typeof fetchFn !== "function") {
      throw new TypeError(options.fetch === undefined ? "fetch is not available" : "fetch must be a function");
    }
    this.#fetchFn = bindFetch(fetchFn);
  }

  async sign(input: Request | string | URL, init?: SigV4RequestInit): Promise<Request> {
    const request = resolveClientSignRequest(input, init);
    const signing = this.#resolveSigningOptions(request.init.signing);
    delete request.init.signing;
    assertParsedRequestCanRepresentSignedUrl(request.requestUrl.pathname, signing.service);
    return this.#signResolvedRequest(request, signing);
  }

  async #signResolvedRequest(
    request: ResolvedClientRequest,
    signing: ResolvedSigningOptions,
    preparedBody?: PreparedBody
  ): Promise<Request> {
    request.signal?.throwIfAborted();
    const signed = await signAwsRequestInternal(
      {
        accessKeyId: this.#accessKeyId,
        secretAccessKey: this.#secretAccessKey,
        sessionToken: this.#sessionToken,
        service: signing.service,
        region: signing.region,
        cache: this.#cache,
        unsignedPayload: signing.unsignedPayload,
        signAllHeaders: signing.signAllHeaders,
        unsignableHeaders: signing.unsignableHeaders,
        doubleUrlEncode: signing.doubleUrlEncode,
        signingDate: signing.signingDate,
        signal: request.signal,
        method: request.method,
        url: request.requestUrl.href,
        headers: request.headers,
        body: request.body,
      },
      () => this.#getSecretAccessKeyHash(),
      request.requestUrl,
      preparedBody
    );

    request.signal?.throwIfAborted();
    const signedInit = requestInitForSignedRequest(request.init, signed);
    return createSignedRequest(signed.url, signedInit, signed.headers);
  }

  async fetch(input: Request | string | URL, init?: SigV4RequestInit): Promise<Response> {
    const request = resolveClientFetchRequest(input, init);
    const signing = this.#resolveSigningOptions(request.init.signing);
    delete request.init.signing;
    assertParsedRequestCanRepresentSignedUrl(request.requestUrl.pathname, signing.service);
    const retryableMethod = isIdempotentMethod(request.method);
    const prepared = await prepareFetchRequest(
      request,
      signing,
      this.#sessionToken !== undefined,
      this.#retries > 0 && retryableMethod
    );
    const fetchFn = this.#fetchFn;
    for (let attempt = 0; attempt <= this.#retries; attempt += 1) {
      const signedRequest = await this.#signResolvedRequest(prepared.request, signing, prepared.body);
      const attemptSignal = validateRequestBeforeTransport(signedRequest);
      let response;
      try {
        response = await fetchFn(signedRequest);
      } catch (err) {
        attemptSignal.throwIfAborted();
        if (attempt === this.#retries || !retryableMethod || isAbortError(err, attemptSignal)) {
          throw err;
        }
        await sleep(Math.random() * this.#retryDelayMs(attempt), attemptSignal);
        continue;
      }
      if (attemptSignal.aborted) {
        await cancelResponseBody(response, attemptSignal);
        attemptSignal.throwIfAborted();
      }
      if (prepared.request.redirectPolicy === "manual" && response.redirected) {
        await cancelResponseBody(response, attemptSignal);
        throw new TypeError('SigV4Client.fetch custom transport followed a redirect despite redirect: "manual"');
      }
      if (prepared.request.redirectPolicy === "error" && isRedirectResponse(response)) {
        await cancelResponseBody(response, attemptSignal);
        throw new TypeError("SigV4Client.fetch received a redirect response; redirect targets must be re-signed");
      }
      const retryableResponse = retryableMethod && (response.status >= 500 || response.status === 429);
      if (attempt === this.#retries || !retryableResponse) {
        return response;
      }
      await cancelResponseBody(response, attemptSignal);
      attemptSignal.throwIfAborted();
      await sleep(Math.random() * this.#retryDelayMs(attempt), attemptSignal);
    }
    throw new Error("unreachable retry loop exit");
  }

  #resolveSigningOptions(value: unknown): ResolvedSigningOptions {
    const options = normalizeClientSigningOptions(value);
    const service = options.service ?? this.#service;
    return {
      service,
      region: options.region ?? this.#region,
      unsignedPayload: resolveUnsignedPayload(options.unsignedPayload ?? this.#unsignedPayload, service),
      signAllHeaders: options.signAllHeaders ?? this.#signAllHeaders,
      unsignableHeaders: options.unsignableHeaders ?? this.#unsignableHeaders,
      doubleUrlEncode: resolveDoubleUrlEncode(options.doubleUrlEncode ?? this.#doubleUrlEncode, service),
      signingDate: options.signingDate,
    };
  }

  #getSecretAccessKeyHash(): Promise<string> {
    if (this.#secretAccessKeyHash !== undefined) {
      return this.#secretAccessKeyHash;
    }
    const hash = sha256Hex(this.#secretAccessKey).catch((err: unknown) => {
      if (this.#secretAccessKeyHash === hash) {
        this.#secretAccessKeyHash = undefined;
      }
      throw err;
    });
    this.#secretAccessKeyHash = hash;
    return hash;
  }

  #retryDelayMs(attempt: number): number {
    return Math.min(MAX_RETRY_DELAY_MS, this.#maxRetryDelayMs, this.#initialRetryDelayMs * 2 ** attempt);
  }
}

async function prepareFetchRequest(
  request: ResolvedClientFetchRequest,
  signing: ResolvedSigningOptions,
  hasSessionToken: boolean,
  replay: boolean
): Promise<PreparedFetchRequest> {
  const headers = new Headers(request.headers);
  rejectEmptyHeader(headers, AMZ_CONTENT_SHA256_HEADER);
  validateSignedHeaderValues(headers, {
    service: signing.service,
    signAllHeaders: signing.signAllHeaders,
    unsignableHeaders: signing.unsignableHeaders,
    overwrittenHeaderNames: signerOverwrittenHeaderNames(hasSessionToken),
  });
  const body = await prepareSigningBody(request.body, headers, {
    service: signing.service,
    unsignedPayload: signing.unsignedPayload,
    replay,
    signal: request.signal,
  });
  const out: SigV4RequestInit = {
    ...request.init,
    headers,
  };
  if (body.body === undefined) {
    delete out.body;
  } else {
    out.body = body.body;
  }
  return {
    request: {
      ...request,
      init: out,
      headers,
      body: body.body,
    },
    body,
  };
}

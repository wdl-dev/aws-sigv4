// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { prepareHashedBody, shouldHashPayload, shouldMaterializeBodyForReplay, type PreparedBody } from "./body.js";
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
  assertSignedRequestHeadersPreserved,
  bindFetch,
  defaultMethod,
  isIdempotentMethod,
  mergeDefinedRequestInit,
  mergeHeaders,
  methodForRequest,
  normalizeMethod,
  rejectFetchForbiddenMethod,
  rejectEmptyHeader,
  rejectNoCorsMode,
  rejectRequestBodyForGetHead,
  rejectUsedRequestBody,
  requestBodyForInput,
  requestInitForSignedRequest,
  snapshotRequestInit,
  snapshotRequestInput,
  type RequestInputSnapshot,
} from "./request.js";
import { abortReason, cancelResponseBody, isAbortError, sleep } from "./retry.js";
import { signAwsRequestInternal } from "./signer.js";
import type { SigV4ClientOptions, SigV4RequestInit, SigningKeyCache } from "./types.js";
import { parseRequestUrl } from "./url.js";

interface ReusableRequestOptions {
  defaultService: string;
  defaultUnsignedPayload: boolean | undefined;
  defaultSignAllHeaders: boolean | undefined;
  defaultUnsignableHeaders: readonly string[] | undefined;
  hasClientSessionToken: boolean;
  replayBody: boolean;
}

interface ReusableRequestState {
  init: SigV4RequestInit;
  preparedBody: PreparedBody | undefined;
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

  sign(input: Request | string | URL, init?: SigV4RequestInit): Promise<Request> {
    return this.#sign(input, init);
  }

  async #sign(input: Request | string | URL, init?: SigV4RequestInit, preparedBody?: PreparedBody): Promise<Request> {
    const inputIsRequest = input instanceof Request;
    const inputSnapshot = inputIsRequest ? snapshotRequestInput(input) : undefined;
    const requestUrl = parseRequestUrl(inputSnapshot?.url ?? (input as string | URL));
    const initSnapshot = snapshotRequestInit(init);
    const requestInit = inputSnapshot ? mergeDefinedRequestInit(inputSnapshot.init, initSnapshot) : initSnapshot;
    const signal = requestInit.signal ?? undefined;
    if (signal !== undefined) {
      throwIfSignalAborted(signal);
    }
    const signingOptions = normalizeClientSigningOptions(requestInit.signing);
    delete requestInit.signing;
    rejectNoCorsMode(requestInit.mode);

    let method = requestInit.method;
    let headers = requestInit.headers;
    let body = requestInit.body;

    if (inputSnapshot !== undefined) {
      if (method === undefined) {
        method = inputSnapshot.method;
      }
      headers = mergeHeaders(inputSnapshot.headers, headers);
      rejectUsedRequestBody(inputSnapshot.bodyUsed, body);
      if ((body === undefined || body === null) && inputSnapshot.body) {
        body = inputSnapshot.body;
      }
    }
    const normalizedMethod = normalizeMethod(method === undefined ? defaultMethod(body) : method);
    rejectFetchForbiddenMethod(normalizedMethod);
    rejectRequestBodyForGetHead(normalizedMethod, body);
    const service = signingOptions.service ?? this.#service;
    assertParsedRequestCanRepresentSignedUrl(requestUrl.pathname, service);

    const signed = await signAwsRequestInternal(
      {
        accessKeyId: this.#accessKeyId,
        secretAccessKey: this.#secretAccessKey,
        sessionToken: this.#sessionToken,
        service,
        region: signingOptions.region ?? this.#region,
        cache: this.#cache,
        unsignedPayload: signingOptions.unsignedPayload ?? this.#unsignedPayload,
        signAllHeaders: signingOptions.signAllHeaders ?? this.#signAllHeaders,
        unsignableHeaders: signingOptions.unsignableHeaders ?? this.#unsignableHeaders,
        doubleUrlEncode: signingOptions.doubleUrlEncode ?? this.#doubleUrlEncode,
        signingDate: signingOptions.signingDate,
        signal: requestInit.signal,
        method: normalizedMethod,
        url: requestUrl.href,
        headers,
        body,
      },
      () => this.#getSecretAccessKeyHash(),
      requestUrl,
      preparedBody
    );

    if (signal !== undefined) {
      throwIfSignalAborted(signal);
    }
    assertRequestCanRepresentSignedUrl(signed.url, service);
    const signedInit = requestInitForSignedRequest(requestInit, signed);
    return createSignedRequest(signed.url, signedInit, signed.headers);
  }

  async fetch(input: Request | string | URL, init?: SigV4RequestInit): Promise<Response> {
    const inputIsRequest = input instanceof Request;
    const requestInput = inputIsRequest ? snapshotRequestInput(input) : undefined;
    const requestUrl = parseRequestUrl(requestInput?.url ?? (input as string | URL));
    const signingInput = requestUrl.href;
    const requestInit = snapshotRequestInit(init);
    requestInit.signing = normalizeClientSigningOptions(requestInit.signing);
    rejectNoCorsMode(requestInit.mode ?? requestInput?.init.mode);
    const redirectPolicy = safeFetchRedirect(requestInput?.init.redirect, requestInit.redirect);
    requestInit.redirect = "manual";
    const method = methodForRequest(requestInput, requestInit);
    rejectFetchForbiddenMethod(method);
    if (requestInput !== undefined) {
      rejectUsedRequestBody(requestInput.bodyUsed, requestInit.body);
    }
    rejectRequestBodyForGetHead(method, requestBodyForInput(requestInput, requestInit));
    const service = requestInit.signing.service ?? this.#service;
    assertParsedRequestCanRepresentSignedUrl(requestUrl.pathname, service);
    // Freeze the hook choice before asynchronous body preparation.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    const sign = this.sign;
    const usesDefaultSign = sign === defaultSigV4ClientSign;
    const replayBody = usesDefaultSign && this.#retries > 0 && isIdempotentMethod(method);
    const reusableRequest = await reusableRequestInitForInput(requestInput, requestInit, {
      defaultService: this.#service,
      defaultUnsignedPayload: this.#unsignedPayload,
      defaultSignAllHeaders: this.#signAllHeaders,
      defaultUnsignableHeaders: this.#unsignableHeaders,
      hasClientSessionToken: this.#sessionToken !== undefined,
      replayBody,
    });
    const sourceSignal = reusableRequest.init.signal ?? undefined;
    for (let attempt = 0; attempt <= this.#retries; attempt += 1) {
      const fetchFn = this.#fetchFn;
      let request = usesDefaultSign
        ? await this.#sign(signingInput, reusableRequest.init, reusableRequest.preparedBody)
        : await sign.call(this, signingInput, reusableRequest.init);
      let attemptSignal = validateRequestBeforeTransport(request, sourceSignal);
      if (!usesDefaultSign && sourceSignal !== undefined) {
        try {
          request = new Request(request, { signal: AbortSignal.any([sourceSignal, attemptSignal]) });
        } catch (err) {
          cancelRequestBody(request, err);
          throw err;
        }
        attemptSignal = validateRequestBeforeTransport(request);
      }
      const attemptMethod = request.method;
      const retryableMethod = usesDefaultSign && attemptMethod === method && isIdempotentMethod(method);
      let response;
      try {
        response = await fetchFn(request);
      } catch (err) {
        throwIfSignalAborted(attemptSignal);
        if (attempt === this.#retries || !retryableMethod || isAbortError(err, attemptSignal)) {
          throw err;
        }
        await sleep(Math.random() * this.#retryDelayMs(attempt), attemptSignal);
        continue;
      }
      if (attemptSignal.aborted) {
        await cancelResponseBody(response, attemptSignal);
        throwIfSignalAborted(attemptSignal);
      }
      if (redirectPolicy === "manual" && response.redirected) {
        await cancelResponseBody(response, attemptSignal);
        throw new TypeError('SigV4Client.fetch custom transport followed a redirect despite redirect: "manual"');
      }
      if (redirectPolicy === "error" && isRedirectResponse(response)) {
        await cancelResponseBody(response, attemptSignal);
        throw new TypeError("SigV4Client.fetch received a redirect response; redirect targets must be re-signed");
      }
      const retryableResponse = retryableMethod && (response.status >= 500 || response.status === 429);
      if (attempt === this.#retries || !retryableResponse) {
        return response;
      }
      await cancelResponseBody(response, attemptSignal);
      throwIfSignalAborted(attemptSignal);
      await sleep(Math.random() * this.#retryDelayMs(attempt), attemptSignal);
    }
    throw new Error("unreachable retry loop exit");
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

// Capture the original implementation before callers can replace the public hook.
// eslint-disable-next-line @typescript-eslint/unbound-method
const defaultSigV4ClientSign = SigV4Client.prototype.sign;

async function reusableRequestInitForInput(
  input: RequestInputSnapshot | undefined,
  init: SigV4RequestInit,
  options: ReusableRequestOptions
): Promise<ReusableRequestState> {
  const sourceSignal = init.signal === undefined ? input?.signal : init.signal;
  if (sourceSignal !== undefined && sourceSignal !== null) {
    throwIfSignalAborted(sourceSignal);
  }
  let reusable: ReusableRequestState;
  if (input === undefined) {
    reusable = await reusableRequestInit(init, options);
  } else {
    const inputInit = mergeDefinedRequestInit(input.init, init);
    inputInit.method = init.method ?? input.method;
    inputInit.headers = mergeHeaders(input.headers, init.headers);
    inputInit.signal = init.signal === undefined ? input.signal : init.signal;
    if ((init.body === undefined || init.body === null) && input.body) {
      inputInit.body = input.body;
    }
    reusable = await reusableRequestInit(inputInit, options);
  }
  if (sourceSignal !== undefined && sourceSignal !== null) {
    throwIfSignalAborted(sourceSignal);
  }
  if (sourceSignal === undefined) {
    delete reusable.init.signal;
  } else {
    reusable.init.signal = sourceSignal;
  }
  return reusable;
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

function createSignedRequest(url: string, init: RequestInit, expectedHeaders: Headers): Request {
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

function isRedirectResponse(response: Response): boolean {
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

function throwIfSignalAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw abortReason(signal);
  }
}

function validateRequestBeforeTransport(request: Request, sourceSignal?: AbortSignal): AbortSignal {
  try {
    if (sourceSignal !== undefined) {
      throwIfSignalAborted(sourceSignal);
    }
    const signal = request.signal;
    throwIfSignalAborted(signal);
    rejectNoCorsMode(request.mode);
    if (request.redirect !== "manual") {
      throw new TypeError('SigV4Client.sign() must return a Request with redirect: "manual"');
    }
    return signal;
  } catch (err) {
    cancelRequestBody(request, err);
    throw err;
  }
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

async function reusableRequestInit(
  init: SigV4RequestInit,
  options: ReusableRequestOptions
): Promise<ReusableRequestState> {
  const headers = new Headers(init.headers);
  rejectEmptyHeader(headers, AMZ_CONTENT_SHA256_HEADER);
  const service = init.signing?.service ?? options.defaultService;
  const unsignedPayload = resolveUnsignedPayload(
    init.signing?.unsignedPayload ?? options.defaultUnsignedPayload,
    service
  );
  const unsignableHeaders = (init.signing?.unsignableHeaders ?? options.defaultUnsignableHeaders) as
    readonly string[] | undefined;
  validateSignedHeaderValues(headers, {
    service,
    signAllHeaders: init.signing?.signAllHeaders ?? options.defaultSignAllHeaders,
    unsignableHeaders,
    overwrittenHeaderNames: signerOverwrittenHeaderNames(options.hasClientSessionToken),
  });
  const materializeBody = options.replayBody && shouldMaterializeBodyForReplay(init.body);
  const hashPayload = shouldHashPayload(init.body, headers, unsignedPayload);
  if (
    !materializeBody &&
    !hashPayload &&
    (init.body === undefined ||
      init.body === null ||
      typeof init.body === "string" ||
      init.body instanceof ReadableStream)
  ) {
    return {
      init: {
        ...init,
        headers,
      },
      preparedBody: undefined,
    };
  }
  const body = await prepareHashedBody(init.body, headers, unsignedPayload, materializeBody, init.signal ?? undefined);
  const out: SigV4RequestInit = {
    ...init,
    headers,
  };
  if (body.body !== undefined) {
    out.body = body.body;
  }
  return {
    init: out,
    preparedBody: body.body === init.body ? undefined : body,
  };
}

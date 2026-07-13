// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { prepareSigningBody, type PreparedBody } from "./body.js";
import {
  AMZ_CONTENT_SHA256_HEADER,
  AMZ_DATE_HEADER,
  AMZ_SECURITY_TOKEN_HEADER,
  AUTHORIZATION_HEADER,
  AWS_ALGORITHM,
  AWS_REQUEST,
  HOST_HEADER,
} from "./constants.js";
import { sha256Hex, signatureHex } from "./crypto.js";
import { formatAmzDate, optionalAmzDate } from "./date.js";
import { canonicalHeaderBlock, signerOverwrittenHeaderNames, validateSignedHeaderValues } from "./headers.js";
import {
  normalizeUnsignableHeaders,
  optionalBoolean,
  requireDefinedOption,
  requireSigningCache,
  resolveDoubleUrlEncode,
  resolveUnsignedPayload,
  snapshotSignAwsRequestOptions,
  validateCredentialOptions,
} from "./options.js";
import { defaultMethod, normalizeMethod, rejectEmptyHeader } from "./request.js";
import type { SignAwsRequestOptions, SignedAwsRequest } from "./types.js";
import { canonicalPathname, canonicalQuery, parseRequestUrl, type ParsedRequestUrl } from "./url.js";

export async function signAwsRequest(options: SignAwsRequestOptions): Promise<SignedAwsRequest> {
  const snapshot = snapshotSignAwsRequestOptions(options);
  const signal = snapshot.signal ?? undefined;
  signal?.throwIfAborted();
  const signed = await signAwsRequestInternal(snapshot);
  signal?.throwIfAborted();
  return signed;
}

/** @internal */
export async function signAwsRequestInternal(
  options: SignAwsRequestOptions,
  secretAccessKeyHash?: string | (() => Promise<string>),
  parsedRequestUrl?: ParsedRequestUrl,
  reusablePreparedBody?: PreparedBody
): Promise<SignedAwsRequest> {
  validateCredentialOptions(options, "signAwsRequest options are required");
  const cache = requireSigningCache(options.cache, "cache");
  requireDefinedOption(options.url, "url");

  const requestUrl = parsedRequestUrl ?? parseRequestUrl(options.url);
  const url = requestUrl.url;
  const method = normalizeMethod(options.method === undefined ? defaultMethod(options.body) : options.method);
  const headers = new Headers(options.headers);
  rejectEmptyHeader(headers, AMZ_CONTENT_SHA256_HEADER);
  const unsignedPayload = resolveUnsignedPayload(
    optionalBoolean(options.unsignedPayload, "unsignedPayload"),
    options.service
  );
  const signAllHeaders = optionalBoolean(options.signAllHeaders, "signAllHeaders");
  const unsignableHeaders = normalizeUnsignableHeaders(options.unsignableHeaders, "unsignableHeaders");
  const doubleUrlEncode = resolveDoubleUrlEncode(
    optionalBoolean(options.doubleUrlEncode, "doubleUrlEncode"),
    options.service
  );
  const explicitAmzDate = optionalAmzDate(options.signingDate);
  headers.set(HOST_HEADER, url.host);
  if (options.sessionToken) {
    headers.set(AMZ_SECURITY_TOKEN_HEADER, options.sessionToken);
  }

  validateSignedHeaderValues(headers, {
    service: options.service,
    signAllHeaders,
    unsignableHeaders,
    overwrittenHeaderNames: signerOverwrittenHeaderNames(options.sessionToken !== undefined),
  });
  const canonicalPath = canonicalPathname(requestUrl.pathname, options.service, doubleUrlEncode);

  // fetch() can supply the stable snapshot it already hashed or prepared for replay.
  const preparedBody =
    reusablePreparedBody ??
    (await prepareSigningBody(options.body, headers, {
      service: options.service,
      unsignedPayload,
      replay: false,
      signal: options.signal ?? undefined,
    }));

  // Capture the default clock after body preparation so slow streams do not stale the signature timestamp.
  const amzDate = explicitAmzDate ?? formatAmzDate(new Date());
  const date = amzDate.slice(0, 8);
  const credentialScope = `${date}/${options.region}/${options.service}/${AWS_REQUEST}`;

  headers.set(AMZ_DATE_HEADER, amzDate);

  const canonicalPayloadHash = preparedBody.payloadHash;
  const { canonicalHeaders, signedHeaders } = canonicalHeaderBlock(url, headers, {
    service: options.service,
    signAllHeaders,
    unsignableHeaders,
  });
  const canonicalRequest = [
    method,
    canonicalPath,
    canonicalQuery(requestUrl.search),
    `${canonicalHeaders}\n`,
    signedHeaders,
    canonicalPayloadHash,
  ].join("\n");
  const stringToSign = [AWS_ALGORITHM, amzDate, credentialScope, await sha256Hex(canonicalRequest)].join("\n");
  const resolvedSecretAccessKeyHash =
    typeof secretAccessKeyHash === "function" ? await secretAccessKeyHash() : secretAccessKeyHash;
  const signature = await signatureHex({
    secretAccessKey: options.secretAccessKey,
    secretAccessKeyHash: resolvedSecretAccessKeyHash,
    date,
    region: options.region,
    service: options.service,
    stringToSign,
    cache,
  });

  headers.set(
    AUTHORIZATION_HEADER,
    [
      `${AWS_ALGORITHM} Credential=${options.accessKeyId}/${credentialScope}`,
      `SignedHeaders=${signedHeaders}`,
      `Signature=${signature}`,
    ].join(", ")
  );

  return {
    method,
    url: requestUrl.href,
    headers,
    body: preparedBody.body,
  };
}

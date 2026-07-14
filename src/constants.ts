// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

export const textEncoder = new TextEncoder();

export const AUTHORIZATION_HEADER = "authorization";
export const HOST_HEADER = "host";
export const AMZ_CONTENT_SHA256_HEADER = "x-amz-content-sha256";
export const AMZ_DATE_HEADER = "x-amz-date";
export const AMZ_SECURITY_TOKEN_HEADER = "x-amz-security-token";
export const CONTENT_TYPE_HEADER = "content-type";

export const MANDATORY_SIGNED_HEADERS = new Set([
  HOST_HEADER,
  AMZ_CONTENT_SHA256_HEADER,
  AMZ_DATE_HEADER,
  AMZ_SECURITY_TOKEN_HEADER,
]);

export const DEFAULT_UNSIGNABLE_HEADERS = new Set([
  AUTHORIZATION_HEADER,
  "accept-encoding",
  "connection",
  "content-length",
  "expect",
  "keep-alive",
  "presigned-expires",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "user-agent",
  "x-amzn-trace-id",
]);

export const AWS_ALGORITHM = "AWS4-HMAC-SHA256";
export const AWS_REQUEST = "aws4_request";
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

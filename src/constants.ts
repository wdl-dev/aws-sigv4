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

export const RFC3986_EXTRA_ESCAPE_RE = /[!'()*]/g;
export const LOWER_HEX = "0123456789abcdef";
export const AWS_ALGORITHM = "AWS4-HMAC-SHA256";
export const AWS_REQUEST = "aws4_request";
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
export const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/u;
export const WHITESPACE_RE = /\s/u;
export const AUTH_PARAM_SEPARATOR_RE = /[,=;]/u;
export const HTTP_METHOD_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
export const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/u;
export const SIGNING_DATE_ERROR = "signingDate must be a valid Date, ISO-8601 string, or YYYYMMDDTHHMMSSZ string";
export const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]);

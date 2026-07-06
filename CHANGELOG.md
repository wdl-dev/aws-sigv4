<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

- Breaking: signed header values must now contain only printable ASCII
  characters; tabs, other control characters, and non-ASCII whitespace are no
  longer accepted before canonicalization.
- Breaking: session tokens and credential scope components must now contain
  only printable ASCII characters.
- Breaking: per-request `init.signing` overrides now read only own properties;
  inherited signing option properties are ignored.
- Breaking: string URLs must now include a non-empty host; empty-authority
  forms such as `http:///path` are rejected instead of being reinterpreted by
  the platform URL parser.
- Changed: signed requests that require body materialization may return a
  stable `Uint8Array` body for non-string body inputs such as `ArrayBuffer`,
  `Blob`, `URLSearchParams`, and `ArrayBufferView`.
- Changed: `accept-encoding` is excluded from the default signed header set
  because fetch implementations and HTTP transports may rewrite it.
- Changed: the public cache type now matches the runtime `Map`-like contract.
- Fixed `SigV4Client` recovery after a transient secret hash digest rejection.
- Fixed `SigV4Client.fetch()` retry preparation for one-shot header iterators.
- Fixed retry delay handling so very large delay settings are clamped to the
  platform timeout limit instead of turning into immediate retry loops.
- Documented query plus-sign behavior, clock-skew limits, and standard
  `TypeError` validation failures.
- Added canonical query percent-encoding and non-default port coverage.
- Added selected AWS SigV4 testsuite vectors for canonical URI, canonical
  query, and session-token signing behavior.
- Added S3-compatible integration coverage for object keys containing literal
  URI-reserved characters.
- Refactored source and unit tests into focused modules while keeping the
  published package as a single-file `dist` entry.

## 1.1.0

- Added explicit `doubleUrlEncode` support for AWS services that expect
  double-escaped canonical URI paths.
- Preserved existing path percent-triplets verbatim during default
  single-encoded path signing, including lowercase hex and percent-encoded
  unreserved bytes, so signatures match the exact wire path.
- Matched AWS SDK-style canonical header whitespace folding.
- Added a real AWS S3 integration job backed by GitHub Actions OIDC and a fixed
  least-privilege test bucket.
- Added ESLint and Prettier checks to local verification, CI, and release
  validation.
- Gated release tags on successful main-branch CI, including the Node 24 and
  real S3 validation jobs.

## 1.0.0

- Switched npmjs publishing to GitHub Actions OIDC trusted publishing after the
  release candidate bootstrap.
- Clarified `signAwsRequest()` raw path input contracts for S3 and non-S3
  services.
- Removed CodeQL-reported defensive and regular-expression hotspots without
  changing signing behavior.
- Simplified local S3-compatible integration test setup.

## 1.0.0-rc.1

- Initial release of a zero-dependency AWS SigV4 signer for Node.js 24+ and
  web-standard runtimes.
- Added `SigV4Client.sign()`, `SigV4Client.fetch()`, and `signAwsRequest()`.
- Added header-based SigV4 signing with real SHA-256 payload hashes by default.
- Added S3-compatible `UNSIGNED-PAYLOAD` support, S3 path/query
  canonicalization coverage, and optional session token signing.
- Added bounded retry support for idempotent `fetch()` requests, including
  transient network failures and abort-aware retry delays.
- Added optional local s3mock integration coverage for S3-compatible smoke
  testing.
- Added CI, release workflow, npm/GitHub Packages publishing configuration, and
  security/contribution documentation.

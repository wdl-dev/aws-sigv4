<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

## 2.0.0

- Breaking: signed header values, session tokens, and credential scope
  components must now contain only printable ASCII characters.
- Breaking: per-request `init.signing` overrides now read only own properties,
  and string URLs must include a non-empty host.
- Changed: signed requests that materialize non-string bodies may return a
  stable `Uint8Array`, `accept-encoding` is excluded from default signing, and
  the public cache type now matches the runtime `Map`-like contract.
- Fixed `SigV4Client` recovery after transient secret hash digest failures,
  one-shot header retry preparation, and oversized retry delay handling.
- Documented stricter signing contracts, query plus-sign behavior, cache and
  credential lifetime, Host replacement, and clock-skew limits.
- Added selected AWS SigV4 testsuite vectors and S3-compatible integration
  coverage for reserved object-key characters.
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

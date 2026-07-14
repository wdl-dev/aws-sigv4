<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

### Breaking changes

- Path signing now follows AWS service defaults: S3 paths remain single-encoded,
  while other services use double-encoded, normalized paths. Explicit
  `doubleUrlEncode` values still override the default; set it to `false` to
  preserve the previous non-S3 behavior.
- `SigV4Client.fetch()` now prevents automatic redirect following and rejects
  `mode: "no-cors"`. Handle a redirect manually and submit its target as a newly
  signed request.
- `Request` input bodies are transferred instead of cloned, avoiding an unread
  tee branch. Create separate requests from replayable bytes when the original
  request must remain reusable.
- `SigV4Client.fetch()` now owns its signing path and no longer invokes an
  overridden `sign()` method. Put logging, instrumentation, and transport policy
  in the custom transport instead.
- Credential `service` and `region` values must be lowercase.
- Request `x-amz-*` headers and S3 `content-md5` can no longer be excluded
  through `unsignableHeaders`; attempted exclusions now throw a `TypeError`.
- `unsignableHeaders` entries must be valid HTTP header names; malformed names
  that were previously ineffective now throw a `TypeError`.
- Retry counts must be non-negative safe integers. Retry counts and delay bounds
  reject explicit `null` instead of treating it as a default.

### Added

- `signAwsRequest()` now accepts a `signal`; cancellation covers body
  materialization and preserves the exact abort reason.
- `SigV4RequestInit` now exposes `duplex?: "half"` for streaming request bodies.
- CI now runs a smoke test on `workerd@1.20260701.1` with compatibility date
  `2026-07-01`, covering Lambda and S3 signatures, signed fetch/retry flow, and
  caller-signal propagation.

### Changed

- Signing and retries now use a stable snapshot of the effective target, request
  state, options, headers, and replayable body bytes. Later caller mutations do
  not change the authenticated request. Retry attempts reuse the materialized
  body and payload hash without repeating library-level snapshotting, body
  materialization, or hashing.
- The custom transport type now reflects its runtime contract as
  `(request: Request) => Promise<Response>`; transports must honor the request
  signal and preserve manual redirect mode.
- The `unsignableHeaders` type now excludes bare strings, matching their existing
  runtime rejection. Use an array, Set, or another object iterable of header
  names.
- `SigningKeyCache.get()` may return `null` as a cache-miss sentinel in addition
  to the standard `undefined` value.
- Client credentials and transport configuration now use native private fields.
  Concurrent cold-cache signing for the same credential scope shares one
  signing-key derivation.

### Fixed

- Raw string URLs now receive the required second path-encoding pass for
  double-encoded services. Raw controls and other characters that cannot survive
  transport unchanged are rejected instead of producing unverifiable signatures.
- Redirect handling now works on workerd, which rejects `redirect: "error"` on
  `Request` construction: transport uses manual mode and the client enforces the
  configured redirect policy on the response.
- Request inputs now inherit their signal and body for `body: null` consistently
  with the platform. Used request bodies, disturbed or locked `ReadableStream`
  bodies, unsupported body objects, non-standard async iterables, and
  Fetch-forbidden client methods are rejected before transport.
- Mutable binary, Blob, FormData, URLSearchParams, and stream bodies are stable
  whenever hashing or retry replay requires fixed bytes, including S3
  `UNSIGNED-PAYLOAD` retries.
- Custom transports now fail closed if they follow a redirect or return after
  cancellation. Abort reasons are preserved through body handling, transport,
  response cleanup, and retry waits.
- Malformed UTF-16 secret access keys are now rejected because UTF-8 replacement
  could otherwise alias distinct JavaScript strings; well-formed Unicode secrets
  remain supported.

### Documentation

- Clarified that payload signing does not replace HTTPS, plaintext HTTP is only
  suitable for trusted local emulators, and workerd does not expose browser-style
  no-cors semantics.
- Defined the supported runtime and custom-transport contracts, materialized-body
  memory costs, signed-header rules, cache lifetime, and real AWS S3 integration
  test responsibilities.

### Tooling and release

- Package validation now enforces an exact file allowlist, installs the produced
  tarball, compiles a strict TypeScript consumer, and runs an ESM runtime smoke
  test.
- S3 integration tests now require an explicit local or AWS mode instead of
  silently skipping.
- Release publishing now retains and sends the same validated tarball to npmjs
  and GitHub Packages after the required main-branch Node and AWS CI jobs pass.

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

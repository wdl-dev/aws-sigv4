<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

### Documentation

- Corrected the 3.0.2 and 3.0.3 notes to distinguish the 3.0.2 `Uint8Array`
  copy-strategy regression from the broader view hardening first shipped in
  3.0.3. Releases before 3.0.3 could snapshot out-of-bounds non-Uint8 typed
  arrays as empty bodies or allow non-Uint8 typed-array and DataView subclass
  accessors to substitute different bytes.

## 3.0.3

### Fixed

- Reverted the 3.0.2 `Uint8Array` view-and-slice copy strategy after it regressed
  large-body latency in workerd, and adopted constructor-based copies for direct
  `ArrayBuffer` and all `ArrayBufferView` bodies.
- Fixed typed-array and DataView snapshots to use intrinsic view state. This
  rejects out-of-bounds non-Uint8 typed arrays instead of signing empty bodies
  and prevents non-Uint8 typed-array and DataView subclass accessors from
  substituting different bytes.

## 3.0.2

### Changed

- Changed `Uint8Array` body snapshots from constructor copying to an intrinsic
  base view followed by `slice()`. This preserved exact bounds and isolated its
  subclass hooks, but regressed large-body copy latency in workerd. Version
  3.0.3 restored constructor copying while retaining and extending the intrinsic
  bounds and subclass isolation.

## 3.0.1

### Fixed

- Discarded response bodies no longer wait for cancellation to finish; cleanup
  remains best-effort even when an underlying stream never settles its
  cancellation promise, so retries and errors can still make progress.

## 3.0.0

### Breaking changes

- Path signing now follows AWS service defaults: S3 paths remain single-encoded,
  while other services use double-encoded, normalized paths. Explicit
  `doubleUrlEncode` values still override the default; set it to `false` to
  preserve the previous non-S3 behavior.
- `SigV4Client.fetch()` now owns its signing path and no longer invokes an
  overridden `sign()` method. Put logging, instrumentation, and transport policy
  in the custom transport instead.
- `SigV4Client.fetch()` now sends with `redirect: "manual"`, rejects automatic
  redirect following, and rejects `mode: "no-cors"`. Submit an accepted redirect
  target as a new signed request.
- `Request` input bodies are transferred instead of cloned, avoiding an unread
  tee branch. Create separate requests from replayable bytes when the original
  request must remain reusable.
- Credential `service` and `region` values must be lowercase. Entries in
  `unsignableHeaders` must be valid header names and can no longer exclude
  request `x-amz-*` headers or S3 `content-md5`.
- Retry counts must be non-negative safe integers. Retry counts and delay bounds
  reject explicit `null` instead of treating it as a default.

### Added

- `signAwsRequest()` now accepts a `signal`, and `SigV4RequestInit` exposes
  `duplex?: "half"` for streaming request bodies.

### Changed

- Signing and retries now use a stable snapshot of the effective target, request
  state, options, headers, and mutable or replayable body data. Retry attempts
  reuse the materialized body and payload hash without repeating library-level
  snapshotting, materialization, or hashing.
- Public types now match the runtime contracts: custom transports use
  `(request: Request) => Promise<Response>`, `unsignableHeaders` excludes bare
  strings, and `SigningKeyCache.get()` may return `null` for a cache miss.
- Client credentials and transport configuration use native private fields, and
  concurrent cold-cache signing for one credential scope shares a signing-key
  derivation.

### Fixed

- Raw string URLs now receive the required second path-encoding pass for
  double-encoded services. Raw controls and other characters that cannot survive
  transport unchanged are rejected instead of producing unverifiable signatures.
- Request signal/body inheritance now follows platform semantics. Used Request
  bodies, disturbed or locked streams, unsupported body objects, non-standard
  async iterables, and Fetch-forbidden client methods fail before transport;
  bodies remain stable whenever hashing or retry replay requires fixed bytes.
- Redirect handling now works on workerd. Custom transports fail closed after
  redirects or cancellation, and exact abort reasons propagate through body
  handling, transport, response cleanup, and retry waits.
- Malformed UTF-16 secret access keys are now rejected because UTF-8 replacement
  could otherwise alias distinct JavaScript strings; well-formed Unicode secrets
  remain supported.

### Documentation and tooling

- Documented the supported runtime, HTTPS, body-memory, signed-header, cache,
  custom-transport, and real AWS S3 integration contracts.
- CI now exercises Lambda and S3 behavior on pinned `workerd@1.20260701.1` with
  compatibility date `2026-07-01`.
- Package validation checks the exact tarball and a strict consumer; S3
  integration requires an explicit mode, and both registries receive the same
  validated artifact after the required main-branch CI jobs pass.

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

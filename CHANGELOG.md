<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

## Unreleased

- Breaking: path signing now follows AWS-style service defaults, using
  single-encoded paths for `service: "s3"` and double-encoded, normalized paths
  for other services; explicit `doubleUrlEncode` values still override the
  default.
- Breaking: `SigV4Client.fetch()` now disables automatic redirects, uses an
  error-on-redirect policy by default, permits manual redirect handling, and
  rejects `redirect: "follow"`; signed requests also reject `mode: "no-cors"`.
- Breaking: `Request` input bodies are transferred directly instead of being
  cloned, avoiding an unread tee branch while making the original request body
  unavailable after the signed request consumes it.
- Breaking: `SigV4Client.fetch()` disables automatic retries whenever `sign()`
  is overridden, including logging or instrumentation wrappers that delegate
  unchanged to `super.sign()`, because the client cannot prove that an arbitrary
  hook preserved the first attempt's target, body, and conditional headers.
- Breaking: credential `service` and `region` values must now be lowercase and
  are rejected rather than silently normalized or signed into an invalid scope.
- Hid client credentials and transport state in native private fields and
  verified that runtime request guards preserve authorization and signed headers.
- Added abort-aware body materialization and retry-response cleanup, exact
  abort-reason propagation, and a lower-level `signAwsRequest()` signal option.
- Added a CI smoke test pinned to `workerd@1.20260701.1`, covering a golden
  signature and the signed fetch/retry path on compatibility date `2026-07-01`.
- Fixed raw-string double path encoding, rejected non-transportable raw control
  characters, and made default redirect rejection compatible with workerd.
- Matched platform `Request` inheritance for signals and `body: null`, rejected
  used request bodies and non-standard async-iterable bodies, and documented
  runtime-specific signed-header and transport-extension constraints.
- Snapshotted mutable URL targets, ordinary option bags, Request state, headers,
  and hashed or replayed body bytes so normal asynchronous work and retries
  cannot change the signed request.
- Reused `fetch()`'s private prepared body across signing attempts instead of
  copying materialized request bytes again for every attempt, without retaining
  temporary UTF-8 copies of string bodies, bypassing overridden `sign()` hooks,
  or reactivating stale prepared bytes after a hook changes request state.
- Clarified that `UNSIGNED-PAYLOAD` does not protect bodies sent over plaintext
  HTTP, that payload signing cannot replace HTTPS, and that workerd does not
  expose browser-style no-cors request semantics.
- Rejected non-manual redirect modes returned by overridden `sign()` methods
  before a custom transport can follow a redirect with signed credentials, and
  prevented hooks from reintroducing `no-cors` or dropping the caller's signal;
  hook-returned request bodies are canceled when these checks reject before
  transport.
- Required every request `x-amz-*` header and S3 `content-md5` header to remain
  signed, narrowed custom fetch transports to their actual one-Request contract,
  failed closed when transports return after abort or follow manual redirects,
  rejected Fetch-forbidden client methods before body consumption, and canceled
  invalid body streams.
- Rejected unsupported body objects on unsigned as well as hashed payload paths,
  and documented the focused runtime contract: standard same-realm Web API
  objects and trusted callers and transports.
- Made the repository-specific builder validate a complete temporary output
  before replacing `dist`; package validation now installs one real tarball,
  compiles a strict TypeScript consumer, and runs an ESM import/constructor
  smoke test against it.
- Restricted retry counts to non-negative safe integers and rejected explicit
  `null` retry counts and delay bounds.
- Shared concurrent signing-key derivation for matching cold-cache credential
  scopes and removed each in-flight entry after success or failure.
- Rejected malformed UTF-16 secret access keys before UTF-8 encoding can alias
  distinct JavaScript strings, clarified why valid Unicode secrets remain
  supported, documented materialized-body memory responsibility, and clarified
  real AWS S3 test resource usage.
- Made package contents an exact allowlist, made the S3 integration command fail
  instead of silently skipping without an explicit mode, and made both registries
  publish the exact tarball accepted by package validation and retained for
  failed-job recovery.

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

<!--
SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
SPDX-License-Identifier: Apache-2.0
-->

# @wdl-dev/aws-sigv4

[![CI](https://github.com/wdl-dev/aws-sigv4/actions/workflows/ci.yml/badge.svg)](https://github.com/wdl-dev/aws-sigv4/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@wdl-dev/aws-sigv4.svg)](https://www.npmjs.com/package/@wdl-dev/aws-sigv4)
[![license](https://img.shields.io/npm/l/@wdl-dev/aws-sigv4.svg)](LICENSE)
[![node](https://img.shields.io/node/v/@wdl-dev/aws-sigv4.svg)](package.json)

Small zero-dependency AWS Signature Version 4 signer for web-standard runtimes,
with focused coverage for JSON AWS APIs and S3-compatible object storage.
The supported baseline is Node.js 24+; other runtimes need equivalent ES2025 and
Web API support. CI also runs a smoke test on the pinned `workerd@1.20260811.1`
release with compatibility date `2026-07-01`.
Web API inputs must be standards-compliant objects created by the active runtime;
cross-realm objects and arbitrary polyfills are outside the supported input
contract. Callers and custom transports are trusted. Monkey-patched platform
instances and prototype-polluted option bags are not security boundaries provided
by this package.

It intentionally implements only a narrow HTTP signing surface:

- explicit `service` and `region`
- header-based SigV4 authorization
- optional session tokens
- real SHA-256 payload hashes for non-S3 requests by default
- S3-compatible `UNSIGNED-PAYLOAD` mode
- a `SigV4Client` wrapper with `sign()` and `fetch()`

It does not implement credential providers, presigned URLs, endpoint discovery,
AWS SDK commands, waiters, or paginators.

```js
import { SigV4Client } from "@wdl-dev/aws-sigv4";

const aws = new SigV4Client({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  sessionToken: process.env.AWS_SESSION_TOKEN,
  service: "lambda",
  region: "ap-northeast-1",
});

const res = await aws.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
  method: "POST",
  headers: {
    "content-type": "application/json",
  },
  body: JSON.stringify({
    imageIdentifier: "arn:aws:lambda:ap-northeast-1:123456789012:microvm-image/demo:1",
    clientToken: "session-001",
  }),
});
```

For S3-compatible object storage that accepts unsigned payload signing:

```js
const s3 = new SigV4Client({
  accessKeyId,
  secretAccessKey,
  service: "s3",
  region: "us-east-1",
  unsignedPayload: true,
});
```

## Local S3 Integration

There is no AWS-official local S3 emulator. For a local wire test, use Adobe
s3mock:

```sh
docker run --rm -p 19500:9090 adobe/s3mock:5.1.0
```

Then run:

```sh
AWS_SIGV4_S3_INTEGRATION=1 npm run test:integration:s3
```

The npm command requires `AWS_SIGV4_S3_INTEGRATION` to be `1`, `s3mock`, or
`aws` and fails when no mode is selected, so a skipped integration test cannot
be mistaken for a successful run.

In local `1` or `s3mock` mode, the integration creates and deletes a temporary
bucket. In `aws` mode, `AWS_SIGV4_S3_BUCKET` is required; the test leaves that
bucket in place and creates objects only under a randomized `runs/` prefix,
which it removes afterward. Both modes put, get, list, and delete objects using
path-style S3 requests signed by this package. Treat the local mode as an
S3-compatible smoke test, not as an AWS S3 semantics or signature oracle.

## Runtime contract

Pass client options, request init values, and per-request signing options as
plain data objects. Only own enumerable fields are part of the supported option
bag contract; values are captured at client construction or operation start.
`service` and `region` must be lowercase. Validation and request representation
failures use standard `TypeError` instances rather than a custom error hierarchy.

Credentials and transport configuration are stored in native ECMAScript private
fields. They are not exposed through enumeration, object spread, or JSON
serialization, but they remain available to a compromised process or debugger.
`SigV4Client` retains the secret access key for its lifetime; create a new client
when credentials rotate.

A client creates an internal signing-key `Map` unless `cache` is supplied. Treat
shared cache keys and values as sensitive process-local material. Caches do not
evict automatically, so long-running processes that sign many date, region, or
service scopes should provide a trusted Map-like cache with application-managed
eviction.

This package does not discover endpoints, refresh credentials, or compensate for
clock skew. Use `signingDate` when the signing time must be controlled.

## Payloads and signed headers

S3 defaults to `UNSIGNED-PAYLOAD`; other services hash request bodies by default.
`UNSIGNED-PAYLOAD` authenticates request metadata but not body bytes. Set
`unsignedPayload: false` when the authorization must bind the payload. Remote
endpoints must still use HTTPS: payload signing does not provide confidentiality,
authenticate responses, or prevent replay of captured signed requests.

An explicit non-empty `x-amz-content-sha256` value becomes the canonical payload
hash. Do not forward that header from untrusted input unless a precomputed hash or
`UNSIGNED-PAYLOAD` is intentional.

Signed header values must contain printable ASCII only. Encode non-ASCII values
before signing; S3 user metadata can use the service's RFC 2047 convention. The
package does not infer application header semantics.

By default, volatile transport headers such as `accept-encoding`,
`content-length`, and `user-agent` are excluded. `signAllHeaders` includes them
except for an existing `authorization` header. `unsignableHeaders` cannot exclude
`host`, SigV4 control headers, request `x-amz-*` headers, or S3 `content-md5`.
`host` always comes from the signed URL.

Set each signed header once with its final value. Repeated values created with
`Headers.append()` are not portable because runtimes may serialize them as one
comma-separated field or multiple field lines; this is especially important on
workerd.

## URL encoding

Path signing uses the effective service after per-request overrides. S3 paths are
single-encoded by default, preserving existing percent triplets for object keys.
Other services default to double-encoded normalized paths: existing percent signs
are escaped, repeated slashes are collapsed, and dot segments are rejected. Set
`doubleUrlEncode: false` for a compatible non-S3 endpoint that requires the old
single-encoded behavior. Query parameters always use standard SigV4 canonical
query encoding.

String URLs preserve their raw path and query for signing after their transport
encoding is determined. `URL` and `Request` inputs already contain platform-
normalized values. `SigV4Client` rejects literal or percent-encoded dot segments
because a web `Request` cannot represent them without normalization; use
`signAwsRequest()` with a raw string URL and a preserving transport when an S3
object key requires them.

Canonical query signing ignores empty segments, preserves explicit empty keys and
duplicate keys, and does not decode form data. A literal `+` is signed as `%2B`;
encode a space as `%20`. Raw whitespace, C0 controls, DEL, backslashes, malformed
percent escapes, and invalid UTF-16 are rejected where they cannot be transported
unchanged.

## Request bodies

All signing APIs default to `POST` when the effective body is present and `GET`
otherwise. Pass an explicit method when the service requires different semantics.

For a `Request` input, init headers merge with and override request headers. An
undefined or null init body inherits the request body directly instead of cloning
and teeing it. A used body is rejected unless replaced. Treat the original input
as consumed; construct independent requests from replayable bytes when both must
remain usable.

Mutable binary and URLSearchParams bodies are always copied when an operation
starts, including when an existing payload hash or `UNSIGNED-PAYLOAD` avoids
hashing their bytes. Later caller mutations cannot change the request, and
hashing and retries reuse that byte snapshot and its payload hash. Standard Blob
bodies are immutable and can be reused directly when their bytes do not need to
be hashed.

Blob and ReadableStream bodies that require hashing, ReadableStream bodies that
require replay, and all FormData bodies are fully buffered without a built-in
size limit. Enforce limits or provide an AbortSignal for large or unbounded
input. Unsigned S3 Blob and stream bodies avoid buffering with `retries: 0`;
non-standard async iterables are rejected.

An explicit init signal overrides a Request input's signal. Omission inherits the
input signal, while `signal: null` disables inheritance. Body materialization
preserves the exact abort reason.

## Retries, redirects, and custom transports

`retries` defaults to `0`; delay defaults are 50 ms initially and 5000 ms maximum.
The retry count must be a non-negative safe integer, and both delay values must
be non-negative finite numbers. Explicit `null` values are rejected rather than
treated as defaults. Configured retries apply to 5xx and 429 responses and
non-abort transport rejections for `GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`.
Delays use full jitter over capped exponential backoff; `Retry-After` is not
interpreted. Keep retries disabled when a nominally idempotent operation is not
safe to replay at the application layer.

`fetch()` owns its signing path and does not call an overridden `client.sign()`
method. Use a custom transport for logging, instrumentation, or transport policy
without changing retry semantics.

Automatic redirect following is disabled because signatures are bound to the
original URL. Transport requests always use `redirect: "manual"` for workerd
compatibility. The default policy rejects redirect responses; an explicit
`redirect: "manual"` returns them, while `redirect: "follow"` is rejected before
body consumption. Validate an accepted target and submit it as a new signed
request.

`mode: "no-cors"` is rejected where the runtime exposes it because required
headers may be stripped. The client verifies that Authorization and signed
headers survive Request construction. Browser callers still need appropriate
CORS permission; workerd does not expose browser-style no-cors semantics.

A custom transport receives one signed `Request` and returns a
`Promise<Response>`. It must honor the request signal, stop I/O on abort, and
preserve manual redirect mode. The effective signal covers body preparation,
transport, and retry waits, with no implicit deadline. Discarded response bodies
are cancelled best-effort, but cleanup completion never delays a retry or error.
Use `AbortSignal.timeout()` when needed.

Only standard Request state is copied. Runtime-specific fetch options, such as
undici's `dispatcher`, are not represented by the Web `Request` API and cannot be
recovered from an input request when it is rebuilt for signing. Unknown init
fields are outside the supported contract even if a runtime currently forwards
them. Capture extensions in the transport closure, for example
`fetch: (request) => fetch(request, { dispatcher })`, or handle them in a separate
client after calling `signAwsRequest()`.

## API reference

### `new SigV4Client(options)`

Requires `accessKeyId`, `secretAccessKey`, `service`, and `region`. Optional
values are `sessionToken`, `cache`, `retries`, `initialRetryDelayMs`,
`maxRetryDelayMs`, `unsignedPayload`, `signAllHeaders`, `unsignableHeaders`,
`doubleUrlEncode`, and `fetch`.

### `client.sign(input, init)`

Returns a signed `Request`. Input may be a Request, string URL, or URL object.
`init.signing` can override `signingDate`, `service`, `region`, `unsignedPayload`,
`signAllHeaders`, `unsignableHeaders`, and `doubleUrlEncode`, but not credentials
or cache configuration.

### `client.fetch(input, init)`

Signs and sends a request using the configured transport. The effective URL,
Request state, init fields, and headers are captured at entry. Bodies that require
hashing or retry replay are materialized before transport, and retries reuse the
resulting bytes. Fetch-forbidden `CONNECT`, `TRACE`, and `TRACK` methods are
rejected before body consumption.

### `signAwsRequest(options)`

Returns `{ method, url, headers, body }` without sending it. Use this when another
HTTP client owns transport or a raw S3 path must be preserved. Materialized bodies
may be returned as a stable Uint8Array snapshot. The optional signal cancels body
materialization and preserves its exact reason.

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
Web API support.
Inputs are ordinary standards-compliant Web API objects created by the active
runtime. Cross-realm objects, arbitrary polyfills, monkey-patched platform
instances, prototype-polluted option bags, and hostile custom transports are not
security boundaries provided by this package; callers and transports are trusted.

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

The integration creates a temporary bucket, puts, gets, lists, and deletes
objects using path-style S3 requests signed by this package. Treat it as an
S3-compatible smoke test, not as an AWS S3 semantics or signature oracle.

## API

### `new SigV4Client(options)`

Required options are `accessKeyId`, `secretAccessKey`, `service`, and `region`.
Optional options are `sessionToken`, `cache`, `retries`, `initialRetryDelayMs`,
`maxRetryDelayMs`, `unsignedPayload`, `signAllHeaders`, `unsignableHeaders`,
`doubleUrlEncode`, and `fetch`.
Pass option bags as plain data objects. Configuration is read when a client is
created or a lower-level signing call starts.

A custom `fetch` transport receives exactly one fully signed `Request` and must
return a `Promise<Response>`. It does not need to accept string or `URL` inputs,
or a separate `RequestInit` argument. It must observe `Request.signal`, stop its
underlying I/O when aborted, and preserve `redirect: "manual"` without following
the redirect itself. The client rejects a response returned after abort and a
detectably followed manual redirect, but it cannot undo I/O already performed by
a transport that ignored these obligations.

`service: "s3"` defaults to `UNSIGNED-PAYLOAD`. Other services hash the request
body by default. `UNSIGNED-PAYLOAD` signs the request metadata but not the body
bytes; set `unsignedPayload: false` when `Authorization` must bind the payload
contents. `retries` defaults to `0`, `initialRetryDelayMs` defaults to `50`,
and `maxRetryDelayMs` defaults to `5000`. `retries` must be a non-negative safe
integer, both delay values must be non-negative finite numbers, and explicit
`null` values are rejected rather than treated as defaults. Path encoding
follows AWS-style service defaults: `doubleUrlEncode` defaults to `false` for
`service: "s3"` and `true` for other services. An explicit value always
overrides the service default.

If you pass a shared `cache`, treat it as sensitive process-local material. Cache
keys do not contain the raw secret access key, but cache values are derived
SigV4 signing keys. `SigV4Client` creates an internal `Map` when `cache` is not
provided, and signing key caches do not evict entries automatically. Long-running
processes that sign many date, region, or service scopes should provide a cache
and manage eviction at the application boundary. Custom cache objects are
trusted `Map`-like objects; do not pass caches from untrusted input.

Credentials and transport configuration are stored in native ECMAScript private
fields. They do not appear in property enumeration, object spread, or JSON
serialization, and assigning a same-named public property does not alter the
signer state. This limits accidental disclosure and mutation; it does not protect
credentials from a compromised process or debugger. A caller-provided `cache`
remains accessible to that caller and must still be treated as sensitive.

If you provide `x-amz-content-sha256`, that non-empty value is signed as the
canonical payload hash. Do not forward this header from untrusted input unless
you intentionally use a precomputed payload hash or `UNSIGNED-PAYLOAD`.

`SigV4Client` keeps `secretAccessKey` for the client lifetime so it can sign
future requests. For temporary or rotated credentials, create a new client and
release references to the old one.

This package does not discover or compensate for service clock skew; pass
`signingDate` when the signing time must be controlled. Validation and request
representation failures throw standard `TypeError` instances rather than a
custom error hierarchy.

Signed header values must contain only printable ASCII characters (`0x20`
through `0x7E`). Some runtime `Headers` implementations may reject unsupported
values before this package can report its own validation error.
Encode non-ASCII values before passing them to the signer. In particular, S3
user metadata that needs non-ASCII text should be encoded using the service's
RFC 2047 convention; this package does not infer or transform application header
semantics.
Signer validation failures are checked before stream bodies are consumed where
possible; platform `RequestInit` validation errors may still be reported by the
runtime when the final `Request` is constructed.

`mode: "no-cors"` is rejected because a runtime may silently remove headers that
SigV4 requires. After constructing a signed `Request`, the client verifies that
`Authorization` and every signed header other than runtime-owned `Host` survived
request guards unchanged. Browser cross-origin requests still require the
destination to grant the appropriate CORS origin, method, and header permissions.

By default, signing excludes volatile hop-by-hop and transport headers such as
`accept-encoding`, `content-length`, and `user-agent`. `signAllHeaders` signs
otherwise excluded headers except existing `authorization` headers. Avoid
signing headers that your `fetch` implementation or HTTP transport may rewrite.
`unsignableHeaders` adds names to the default exclusion set. It cannot exclude
`host`, `x-amz-content-sha256`, `x-amz-date`, `x-amz-security-token`, any
`x-amz-*` header present in the request, or `content-md5` from an S3 request;
attempts to do so are rejected. `host` is derived from the signed URL; any
caller-provided `Host` header is replaced before signing, and `client.fetch()`
sends the replaced value.

Set each signed header once with its final value. Repeated values created with
`Headers.append()` are not portable: runtimes can serialize them as either one
comma-separated field or multiple field lines, which changes the canonical
value reconstructed by AWS. This is particularly important in workerd-based
runtimes.

`client.sign()` and `client.fetch()` accept `init.signing` to override
per-request signing options such as `signingDate`, `service`, `region`,
`unsignedPayload`, `signAllHeaders`, `unsignableHeaders`, or `doubleUrlEncode`;
it cannot override credentials or `cache`. Pass `init` and `init.signing` as
plain data objects; their enumerable fields are snapshotted when the operation
starts.

`client.sign()`, `client.fetch()`, and `signAwsRequest()` default `method` to
`POST` when the effective body is present and to `GET` otherwise. Pass an
explicit method when the target service requires different semantics.

### `client.sign(input, init)`

Returns a signed `Request`. `input` may be a `Request`, string URL, or `URL`.
When `input` is a `Request`, `init.headers` are merged with the request headers
and override duplicate names; they do not replace the request headers wholesale.

When a `Request` input supplies the body and `init.body` is `undefined` or
`null`, the client uses that body stream directly instead of cloning and teeing
it. This matches the platform's `Request` inheritance semantics and avoids an
unread clone branch retaining streamed bytes. A request whose body is already
used is rejected unless a replacement body is supplied. Treat the original
input request as consumed: hashed bodies can be read during signing, and
consuming the returned signed request makes the original body unusable.
Construct independent requests from replayable bytes when both requests must
remain usable. `init.signal` overrides the input request's signal; when it is
omitted, the input signal is inherited. An explicit `signal: null` disables that
inheritance. Aborts cancel in-progress body materialization and propagate their
exact reason.
When payload hashing or retry replay requires materialization, mutable
`ArrayBuffer`, `ArrayBufferView`, `Uint8Array`, and `URLSearchParams` bodies are
snapshotted so the hashed bytes and every transmitted attempt remain identical.
Standard `Blob` bodies are immutable and can be reused directly.

`URL` and `Request` inputs are already normalized by the platform URL parser.
For raw paths that contain literal `.` or `..` path segments, use
`signAwsRequest()` with a string URL and a transport that preserves the exact
path. `SigV4Client` rejects paths with literal or percent-encoded dot segments
because a web `Request` cannot represent them without path normalization.

Canonical query signing ignores empty query segments, so `?a=1&&b=2` signs the
same canonical query as `?a=1&b=2`. Explicit empty keys such as `?=value` are
preserved. Query components are not decoded as form data before signing: a
literal `+` is signed as `%2B`, while a space must be sent as `%20`. Avoid raw
`+` in query strings when the receiving service interprets it as a space.

Path signing uses the effective request service after per-request overrides.
`service: "s3"` keeps single-encoded object-key semantics: existing path
percent-triplets are signed exactly as they appear on the wire, including
lowercase hex and percent-encoded unreserved bytes such as `%7E` or `%41`.
Other services default to AWS-style double encoding: existing percent-encoded
bytes have their `%` escaped, repeated slashes are collapsed, and dot segments
are rejected before signing. For string URLs, literal Unicode and ASCII
characters escaped by the WHATWG URL parser are first converted to their wire
encoding, so string and `URL` inputs produce the same double-encoded signature.
Literal path characters outside the unreserved set are URI-encoded in either
mode. Raw whitespace, C0 controls, DEL, and backslashes are rejected because
they cannot be transported without normalization. Pass `doubleUrlEncode: false`
explicitly for a non-S3 service or compatible endpoint that requires
single-encoded paths. The option applies only to the path; query parameters
always use normal SigV4 canonical query encoding.

### `client.fetch(input, init)`

Signs and sends the request with the configured `fetch` implementation. A `URL`
input is snapshotted before asynchronous body work, and every retry uses that
same target. The client rejects Fetch-forbidden `CONNECT`, `TRACE`, and `TRACK`
methods before consuming a body; use `signAwsRequest()` with a custom non-Fetch
transport when one of those methods must be signed.

With `retries` greater than `0`, it retries HTTP 5xx and 429 responses only for
idempotent methods (`GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`). It also
retries all non-abort `fetch` rejections for those methods; the Web Fetch API
does not expose a portable transient/permanent classification. Retry delays use
full jitter between `0` and the capped exponential backoff delay; `Retry-After`
response headers are not read.
`FormData` signing always buffers the body to generate a stable multipart
boundary. Unsigned S3 `ReadableStream` bodies avoid full buffering when
`retries: 0`; keep `retries: 0` for large streaming uploads. Non-standard async
iterable bodies are rejected; wrap byte chunks in a web `ReadableStream`.
For S3-compatible or custom AWS-compatible services where `PUT` or `DELETE` are
not safe to replay at the application layer, keep `retries: 0` or enable retries
only around requests that are known to be safe.

Automatic redirect following is disabled because a SigV4 authorization value is
bound to the original URL. For compatibility with workerd, `client.fetch()`
always constructs the transport request with `redirect: "manual"`. Its default
policy still has `"error"` semantics: a redirect response is detected and
rejected. An explicit `redirect: "manual"` returns that response, while
`redirect: "follow"` is rejected before the body is consumed. If a manual
redirect is accepted by the application, validate its target and submit it as a
separate signed request.

The effective signal covers body materialization, the signed request transport,
retry-response cleanup, and retry waits. The client preserves an explicit abort
reason, including non-Error values. No implicit request deadline is added; use
`AbortSignal.timeout()` (or a combined application signal) when calls need a
deadline.

Only standard `Request` state can be copied from a `Request` input. Runtime
extensions without standard getters, such as undici's `dispatcher`, are not
recoverable when the signed request is rebuilt, and per-request init extensions
cannot be forwarded through the custom transport's one-`Request` contract.
Configure them in the transport closure instead, for example
`fetch: (request) => fetch(request, { dispatcher })`, or use
`signAwsRequest()` and let another HTTP client send the signed result.

### `signAwsRequest(options)`

Lower-level helper that returns `{ method, url, headers, body }` without sending
the request. Use this when another HTTP client owns transport, or when S3 object
keys need raw string URL paths that web `Request` would normalize.
When a body is materialized for hashing, the returned `body` may be a stable
`Uint8Array` snapshot containing the signed bytes rather than the original body
object.
It accepts the same signing options as `SigV4Client`, including
`doubleUrlEncode`, plus an optional `signal` that cancels body materialization
and propagates its exact abort reason.
It preserves string URL paths exactly in the returned `url`. For S3, pass object
key paths in percent-encoded form. Raw whitespace, C0 controls, DEL,
backslashes, and malformed percent escapes are rejected. For non-S3 services,
literal Unicode and other characters escaped by a web `Request` are signed from
their wire encoding before the second encoding layer is applied. Literal `.`
and `..` path segments are required for some S3 object keys; with
`doubleUrlEncode: true`, non-S3 paths reject dot segments and collapse repeated
slashes before path escaping.

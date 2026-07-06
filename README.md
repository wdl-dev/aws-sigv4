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

The integration creates a temporary bucket, puts, gets, lists, and deletes
objects using path-style S3 requests signed by this package. Treat it as an
S3-compatible smoke test, not as an AWS S3 semantics or signature oracle.

## API

### `new SigV4Client(options)`

Required options are `accessKeyId`, `secretAccessKey`, `service`, and `region`.
Optional options are `sessionToken`, `cache`, `retries`, `initialRetryDelayMs`,
`maxRetryDelayMs`, `unsignedPayload`, `signAllHeaders`, `unsignableHeaders`,
`doubleUrlEncode`, and `fetch`.

`service: "s3"` defaults to `UNSIGNED-PAYLOAD`. Other services hash the request
body by default. `UNSIGNED-PAYLOAD` signs the request metadata but not the body
bytes; set `unsignedPayload: false` when `Authorization` must bind the payload
contents. `retries` defaults to `0`, `initialRetryDelayMs` defaults to `50`,
and `maxRetryDelayMs` defaults to `5000`.

If you pass a shared `cache`, treat it as sensitive process-local material. Cache
keys do not contain the raw secret access key, but cache values are derived
SigV4 signing keys. `SigV4Client` creates an internal `Map` when `cache` is not
provided, and signing key caches do not evict entries automatically. Long-running
processes that sign many date, region, or service scopes should provide a cache
and manage eviction at the application boundary. Custom cache objects are
trusted `Map`-like objects; do not pass caches from untrusted input.

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
Signer validation failures are checked before stream bodies are consumed where
possible; platform `RequestInit` validation errors may still be reported by the
runtime when the final `Request` is constructed.

By default, signing excludes volatile hop-by-hop and transport headers such as
`accept-encoding`, `content-length`, and `user-agent`. `signAllHeaders` signs
otherwise excluded headers except existing `authorization` headers. Avoid
signing headers that your `fetch` implementation or HTTP transport may rewrite.
`unsignableHeaders` adds names to the default exclusion set, but mandatory SigV4
headers such as `host`,
`x-amz-content-sha256`, `x-amz-date`, and `x-amz-security-token` are always
signed when present.

`client.sign()` and `client.fetch()` accept `init.signing` to override
per-request signing options such as `signingDate`, `service`, `region`,
`unsignedPayload`, `signAllHeaders`, `unsignableHeaders`, or `doubleUrlEncode`;
it cannot override credentials or `cache`. Only own properties on `init.signing`
are read; inherited signing option properties are ignored.

### `client.sign(input, init)`

Returns a signed `Request`. `input` may be a `Request`, string URL, or `URL`.
When `input` is a `Request`, `init.headers` are merged with the request headers
and override duplicate names; they do not replace the request headers wholesale.

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

Path signing preserves the package's single-encoded default, including for S3
object keys. With the default `doubleUrlEncode: false`, existing path
percent-triplets are signed exactly as they appear on the wire, including
lowercase hex and percent-encoded unreserved bytes such as `%7E` or `%41`.
Literal path characters outside the unreserved set are URI-encoded in the
canonical request.
Set `doubleUrlEncode: true` only for AWS services or endpoints that expect
AWS-style canonical URI escaping for non-S3 paths. It applies only to the path:
literal reserved characters such as `+` and `=` are escaped once, while existing
percent-encoded bytes have their `%` escaped. Query parameters keep the normal
SigV4 canonical query encoding.

### `client.fetch(input, init)`

Signs and sends the request with the configured `fetch` implementation. When
`retries` is greater than `0`, it retries HTTP 5xx and 429 responses only for
idempotent methods (`GET`, `HEAD`, `OPTIONS`, `PUT`, and `DELETE`). It also
retries transient network-level `fetch` rejections for those methods, but not
aborted requests. `FormData` signing always buffers the body to generate a
stable multipart boundary. Unsigned S3 `ReadableStream` bodies avoid full
buffering when `retries: 0`; keep `retries: 0` for large streaming uploads.
For S3-compatible or custom AWS-compatible services where `PUT` or `DELETE` are
not safe to replay at the application layer, keep `retries: 0` or enable retries
only around requests that are known to be safe.

### `signAwsRequest(options)`

Lower-level helper that returns `{ method, url, headers, body }` without sending
the request. Use this when another HTTP client owns transport, or when S3 object
keys need raw string URL paths that web `Request` would normalize.
It accepts the same signing options as `SigV4Client`, including
`doubleUrlEncode`.
It preserves string URL paths exactly. For S3, pass object key paths in
percent-encoded form. For non-S3 services, pass path labels as literal values
and avoid characters that cannot appear on the wire without percent encoding,
such as spaces, literal `%`, or non-ASCII text. Literal `.` and `..` path
segments are required for some S3 object keys; with `doubleUrlEncode: true`,
non-S3 paths reject dot segments and collapse repeated slashes before path
escaping.

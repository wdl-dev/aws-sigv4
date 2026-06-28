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

It intentionally implements only a narrow HTTP signing surface:

- explicit `service` and `region`
- header-based SigV4 authorization
- optional session tokens
- real SHA-256 payload hashes by default
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

The integration creates a temporary bucket, puts, gets, lists, and deletes one
object using path-style S3 requests signed by this package. Treat it as an
S3-compatible smoke test, not as an AWS S3 semantics or signature oracle.

## API

### `new SigV4Client(options)`

Required options are `accessKeyId`, `secretAccessKey`, `service`, and `region`.
Optional options are `sessionToken`, `cache`, `retries`, `initialRetryDelayMs`,
`maxRetryDelayMs`, `unsignedPayload`, `signAllHeaders`, `unsignableHeaders`,
`doubleUrlEncode`, and `fetch`.

`service: "s3"` defaults to `UNSIGNED-PAYLOAD`. Other services hash the request
body by default. `retries` defaults to `0`.

If you pass a shared `cache`, treat it as sensitive process-local material. Cache
keys do not contain the raw secret access key, but cache values are derived
SigV4 signing keys.

### `client.sign(input, init)`

Returns a signed `Request`. `input` may be a `Request`, string URL, or `URL`.
`init.signing` can override per-request signing options such as `signingDate`,
`service`, `region`, `unsignedPayload`, `unsignableHeaders`, or
`doubleUrlEncode`; it cannot override credentials or `cache`.

`URL` and `Request` inputs are already normalized by the platform URL parser.
For raw paths that contain literal `.` or `..` path segments, use
`signAwsRequest()` with a string URL and a transport that preserves the exact
path. `SigV4Client` rejects those string URLs because a web `Request` cannot
represent them without path normalization.

Canonical query signing ignores empty query segments, so `?a=1&&b=2` signs the
same canonical query as `?a=1&b=2`. Explicit empty keys such as `?=value` are
preserved.

Path signing preserves the package's single-encoded default, including for S3
object keys. With the default `doubleUrlEncode: false`, existing path
percent-triplets are signed exactly as they appear on the wire, including
lowercase hex and percent-encoded unreserved bytes such as `%7E` or `%41`.
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

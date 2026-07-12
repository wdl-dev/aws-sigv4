// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  assertHelloStreamReadable,
  helloStream,
  lambdaRequest,
  s3Request,
} from "./helpers.js";
test("S3 signing includes content-type by default", async () => {
  const signed = await s3Request({
    method: "PUT",
    url: `${S3_ENDPOINT}/example-bucket/content-type.txt`,
    headers: {
      "content-type": "text/plain",
    },
    body: "hello",
  });
  assert.match(
    signed.headers.get("authorization") || "",
    /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/
  );
});

test("canonical headers trim and collapse whitespace", async () => {
  const trimmed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "a b",
    },
  });
  const spaced = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "  a   b  ",
    },
  });
  assert.equal(spaced.headers.get("authorization"), trimmed.headers.get("authorization"));
});

test("signing rejects non-printable signed header values", async () => {
  for (const value of ["Résumé.pdf", "a\u00a0b", "a\x7fb", "a\tb"]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
          headers: {
            "x-amz-meta-filename": value,
          },
        }),
      {
        name: "TypeError",
        message: /x-amz-meta-filename header value must contain only printable ASCII characters/,
      }
    );
  }
});

test("signing rejects non-printable signed header values without consuming stream bodies", async () => {
  const body = helloStream();
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "POST",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        headers: {
          "x-amz-meta-filename": "Résumé.pdf",
        },
        body,
      }),
    {
      name: "TypeError",
      message: /x-amz-meta-filename header value must contain only printable ASCII characters/,
    }
  );
  await assertHelloStreamReadable(body);
});

test("mandatory AWS header exclusions are rejected before consuming stream bodies", async () => {
  const body = helloStream();
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "POST",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        headers: {
          "x-amz-meta-owner": "alice",
        },
        body,
        unsignableHeaders: ["x-amz-meta-owner"],
      }),
    /mandatory signed header x-amz-meta-owner/
  );
  await assertHelloStreamReadable(body);
});

test("signing ignores non-printable unsignable header values", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-debug-only": "Résumé.pdf",
    },
    unsignableHeaders: ["x-debug-only"],
  });
  assert.doesNotMatch(signed.headers.get("authorization") || "", /x-debug-only/);
});

test("range is signed by default when present", async () => {
  const signed = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/ranged.txt`,
    headers: {
      range: "bytes=0-99",
    },
  });
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date/);
});

test("signing returns a host header for custom transports", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
  });
  assert.equal(signed.headers.get("host"), "lambda.ap-northeast-1.amazonaws.com");
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=host;x-amz-date/);
});

test("explicit host headers are normalized without duplicate signed headers", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      host: "evil.example.com",
    },
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.equal(signed.headers.get("host"), "lambda.ap-northeast-1.amazonaws.com");
  assert.match(authorization, /SignedHeaders=host;x-amz-date/);
  assert.doesNotMatch(authorization, /SignedHeaders=host;host/);
});

test("signing rejects empty x-amz-content-sha256", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "POST",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        headers: {
          "content-type": "application/json",
          "x-amz-content-sha256": "",
        },
        body: "{}",
      }),
    /x-amz-content-sha256 must not be empty/
  );
});

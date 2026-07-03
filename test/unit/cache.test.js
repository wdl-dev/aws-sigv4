// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXED_AMZ_DATE, LAMBDA_ENDPOINT, SECRET_ACCESS_KEY, lambdaClient, lambdaRequest } from "./helpers.js";

test("external signing key cache keys do not expose the secret access key", async () => {
  const cache = new Map();
  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    cache,
  });
  assert.equal(cache.size, 1);
  for (const key of cache.keys()) {
    assert.equal(key.includes(SECRET_ACCESS_KEY), false);
    assert.match(key, /^sigv4,[0-9a-f]{64},20260616,ap-northeast-1,lambda$/);
  }
});

test("SigV4Client does not cache rejected secret hash promises", async () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  let digestCalls = 0;
  const client = lambdaClient();
  try {
    crypto.subtle.digest = async (algorithm, data) => {
      digestCalls += 1;
      if (digestCalls === 1) {
        throw new Error("digest unavailable");
      }
      return originalDigest(algorithm, data);
    };
    await assert.rejects(
      () =>
        client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /digest unavailable/
    );
    const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(
      signed.headers.get("authorization"),
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482"
    );
    assert.ok(digestCalls > 1);
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

test("signing rejects invalid signing key caches", async () => {
  assert.throws(() => lambdaClient({ cache: {} }), /cache must be a Map-like cache/);
  assert.throws(() => lambdaClient({ cache: new WeakMap() }), /cache must be a Map-like cache/);
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        cache: {},
      }),
    /cache must be a Map-like cache/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        cache: new WeakMap(),
      }),
    /cache must be a Map-like cache/
  );
});

test("SigV4Client computes the secret hash lazily", () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  try {
    crypto.subtle.digest = () => {
      throw new Error("digest should not run during construction");
    };
    assert.doesNotThrow(() => lambdaClient());
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

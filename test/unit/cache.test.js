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

test("external signing key caches reuse entries for matching credential scopes", async () => {
  let cacheWrites = 0;
  const cache = new (class extends Map {
    set(key, value) {
      cacheWrites += 1;
      return super.set(key, value);
    }
  })();

  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    cache,
  });
  assert.equal(cacheWrites, 1);

  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms/second`,
    cache,
  });
  assert.equal(cacheWrites, 1);
  assert.equal(cache.size, 1);
});

test("external signing key caches may return null for missing entries", async () => {
  const entries = new Map();
  let cacheWrites = 0;
  const cache = {
    get(key) {
      return entries.get(key) ?? null;
    },
    set(key, value) {
      cacheWrites += 1;
      entries.set(key, value);
    },
  };

  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    cache,
  });
  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms/second`,
    cache,
  });

  assert.equal(cacheWrites, 1);
  assert.equal(entries.size, 1);
});

test("signAwsRequest skips the secret hash when no signing-key cache is used", async () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  let secretDigestCalls = 0;
  try {
    crypto.subtle.digest = (algorithm, data) => {
      if (bufferSourceText(data) === SECRET_ACCESS_KEY) {
        secretDigestCalls += 1;
      }
      return originalDigest(algorithm, data);
    };
    await lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    });
    assert.equal(secretDigestCalls, 0);
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

test("SigV4Client does not cache rejected secret hash promises", async () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  let secretDigestCalls = 0;
  const client = lambdaClient();
  try {
    crypto.subtle.digest = (algorithm, data) => {
      if (bufferSourceText(data) === SECRET_ACCESS_KEY) {
        secretDigestCalls += 1;
        if (secretDigestCalls === 1) {
          return Promise.reject(new Error("secret digest unavailable"));
        }
      }
      return originalDigest(algorithm, data);
    };
    await assert.rejects(
      () =>
        client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /secret digest unavailable/
    );
    const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(
      signed.headers.get("authorization"),
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482"
    );
    await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(secretDigestCalls, 2);
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

test("SigV4Client shares in-flight secret hash promises", async () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  const client = lambdaClient();
  let releaseSecretDigest;
  let secretDigestStartedResolve;
  let secretDigestCalls = 0;
  const secretDigestStarted = new Promise((resolve) => {
    secretDigestStartedResolve = resolve;
  });
  const secretDigestPromise = new Promise((resolve, reject) => {
    releaseSecretDigest = async () => {
      try {
        resolve(await originalDigest("SHA-256", new TextEncoder().encode(SECRET_ACCESS_KEY)));
      } catch (err) {
        reject(err);
      }
    };
  });
  try {
    crypto.subtle.digest = (algorithm, data) => {
      if (bufferSourceText(data) === SECRET_ACCESS_KEY) {
        secretDigestCalls += 1;
        secretDigestStartedResolve();
        return secretDigestPromise;
      }
      return originalDigest(algorithm, data);
    };

    const first = client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    const second = client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    await secretDigestStarted;
    assert.equal(secretDigestCalls, 1);
    await releaseSecretDigest();

    const [firstSigned, secondSigned] = await Promise.all([first, second]);
    assert.equal(secretDigestCalls, 1);
    assert.equal(firstSigned.headers.get("authorization"), secondSigned.headers.get("authorization"));
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

test("SigV4Client shares in-flight signing-key derivation for one credential scope", async () => {
  let cacheWrites = 0;
  const cache = new (class extends Map {
    set(key, value) {
      cacheWrites += 1;
      return super.set(key, value);
    }
  })();
  const client = lambdaClient({ cache });
  const signed = await Promise.all(
    Array.from({ length: 100 }, () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: { signingDate: FIXED_AMZ_DATE },
      })
    )
  );

  assert.equal(cacheWrites, 1);
  assert.equal(cache.size, 1);
  const authorization = signed[0].headers.get("authorization");
  assert.ok(authorization);
  assert.equal(
    signed.every((request) => request.headers.get("authorization") === authorization),
    true
  );
});

test("SigV4Client does not retain rejected in-flight signing-key derivations", async () => {
  const originalSign = crypto.subtle.sign.bind(crypto.subtle);
  const cache = new Map();
  const client = lambdaClient({ cache });
  let hmacCalls = 0;
  try {
    crypto.subtle.sign = (...args) => {
      hmacCalls += 1;
      if (hmacCalls === 1) {
        return Promise.reject(new Error("HMAC unavailable"));
      }
      return originalSign(...args);
    };
    await assert.rejects(
      () =>
        client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /HMAC unavailable/
    );
    assert.equal(cache.size, 0);
    const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.match(signed.headers.get("authorization") || "", /^AWS4-HMAC-SHA256 /u);
    assert.equal(cache.size, 1);
  } finally {
    crypto.subtle.sign = originalSign;
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

function bufferSourceText(data) {
  if (data instanceof ArrayBuffer) {
    return new TextDecoder().decode(data);
  }
  return new TextDecoder().decode(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
}

// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXED_AMZ_DATE, LAMBDA_ENDPOINT, lambdaClient, lambdaRequest } from "./helpers.js";
test("SigV4Client.fetch retries transient fetch rejections", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      if (calls === 1) {
        throw new TypeError("socket reset");
      }
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(calls, 2);
});

test("SigV4Client.fetch retries 429 responses", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      return new Response(calls === 1 ? "throttle" : "ok", { status: calls === 1 ? 429 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(calls, 2);
});

test("SigV4Client.fetch retries every configured idempotent method", async () => {
  for (const method of ["HEAD", "OPTIONS", "DELETE"]) {
    let calls = 0;
    const client = lambdaClient({
      retries: 1,
      initialRetryDelayMs: 0,
      fetch: async () => {
        calls += 1;
        return new Response(method === "HEAD" ? null : calls === 1 ? "retry" : "ok", {
          status: calls === 1 ? 500 : 200,
        });
      },
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200);
    assert.equal(calls, 2, method);
  }
});

test("SigV4Client.fetch does not retry non-idempotent POST requests", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 3,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      return new Response("retry", { status: 500 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 500);
  assert.equal(calls, 1);
});

test("SigV4Client.fetch does not retry non-idempotent fetch rejections", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 3,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      throw new TypeError("socket reset");
    },
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "POST",
        body: "{}",
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /socket reset/
  );
  assert.equal(calls, 1);
});

test("SigV4Client.fetch does not retry aborted requests", async () => {
  let calls = 0;
  const controller = new AbortController();
  const client = lambdaClient({
    retries: 3,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      controller.abort();
      throw new DOMException("aborted", "AbortError");
    },
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "PUT",
        signal: controller.signal,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /aborted/
  );
  assert.equal(calls, 1);
});

test("SigV4Client.fetch aborts while waiting to retry", async () => {
  const originalSetTimeout = globalThis.setTimeout;
  const originalClearTimeout = globalThis.clearTimeout;
  const timeoutId = {};
  const controller = new AbortController();
  let calls = 0;
  let clearCalls = 0;
  let sleepStartedResolve;
  const sleepStarted = new Promise((resolve) => {
    sleepStartedResolve = resolve;
  });
  try {
    globalThis.setTimeout = () => {
      sleepStartedResolve();
      return timeoutId;
    };
    globalThis.clearTimeout = (id) => {
      if (id === timeoutId) {
        clearCalls += 1;
      }
    };
    const client = lambdaClient({
      retries: 1,
      initialRetryDelayMs: 30_000,
      fetch: async () => {
        calls += 1;
        return new Response("retry", { status: 500 });
      },
    });
    const fetchPromise = client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method: "PUT",
      signal: controller.signal,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    let guardTimeout;
    const waitResult = await Promise.race([
      sleepStarted.then(() => "started"),
      new Promise((resolve) => {
        guardTimeout = originalSetTimeout(() => resolve("timeout"), 1000);
      }),
    ]);
    if (guardTimeout !== undefined) {
      originalClearTimeout(guardTimeout);
    }
    if (waitResult !== "started") {
      throw new Error("retry delay did not start");
    }
    controller.abort(new DOMException("stop retry", "AbortError"));
    await assert.rejects(fetchPromise, /stop retry/);
    assert.equal(calls, 1);
    assert.equal(clearCalls, 1);
  } finally {
    globalThis.setTimeout = originalSetTimeout;
    globalThis.clearTimeout = originalClearTimeout;
  }
});

test("SigV4Client.fetch aborts retry delays immediately", async () => {
  let calls = 0;
  const controller = new AbortController();
  const client = lambdaClient({
    retries: 3,
    initialRetryDelayMs: 30_000,
    fetch: async () => {
      calls += 1;
      controller.abort();
      return new Response("retry", { status: 500 });
    },
  });
  const startedAt = Date.now();
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "PUT",
        signal: controller.signal,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /AbortError|aborted/
  );
  assert.equal(calls, 1);
  assert.ok(Date.now() - startedAt < 1000);
});

test("SigV4Client.fetch cancels retryable response bodies before aborting", async () => {
  let cancelled = 0;
  const controller = new AbortController();
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      controller.abort();
      return new Response(
        new ReadableStream({
          start(innerController) {
            innerController.enqueue(new TextEncoder().encode("retry"));
          },
          cancel() {
            cancelled += 1;
          },
        }),
        { status: 500 }
      );
    },
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "PUT",
        signal: controller.signal,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /AbortError|aborted/
  );
  assert.equal(cancelled, 1);
});

test("SigV4Client.fetch signs Request input payload hashes from the Request body", async () => {
  const bodyHash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
  const url = `${LAMBDA_ENDPOINT}/2025-09-09/microvms`;
  const expected = await lambdaRequest({
    method: "POST",
    url,
    headers: {
      "content-type": "application/json",
      "x-amz-content-sha256": bodyHash,
    },
    body: "{}",
  });
  const client = lambdaClient({
    retries: 0,
    fetch: async (request) => {
      assert.equal(await request.clone().text(), "{}");
      assert.equal(request.headers.get("x-amz-content-sha256"), bodyHash);
      assert.equal(request.headers.get("authorization"), expected.headers.get("authorization"));
      return new Response("ok");
    },
  });
  const response = await client.fetch(
    new Request(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: "{}",
    }),
    {
      signing: { signingDate: FIXED_AMZ_DATE },
    }
  );
  assert.equal(response.status, 200);
});

test("SigV4Client.fetch cancels retryable response bodies before retrying", async () => {
  let calls = 0;
  let cancelled = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      if (calls === 1) {
        return new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("retry"));
            },
            cancel() {
              cancelled += 1;
            },
          }),
          { status: 500 }
        );
      }
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(cancelled, 1);
});

test("SigV4Client.fetch reuses signed payload hashes across retries", async () => {
  let reads = 0;
  class CountingBlob extends Blob {
    async arrayBuffer() {
      reads += 1;
      return super.arrayBuffer();
    }
  }
  let calls = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      return new Response("ok", { status: calls === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: new CountingBlob(["hello"]),
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(reads, 1);
});

test("SigV4Client.fetch retries ReadableStream bodies", async () => {
  const bodies = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      bodies.push(await request.clone().text());
      return new Response("ok", { status: bodies.length === 1 ? 500 : 200 });
    },
  });
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(bodies, ["hello", "hello"]);
});

test("SigV4Client.fetch retries Request ReadableStream bodies", async () => {
  const bodies = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      bodies.push(await request.clone().text());
      return new Response("ok", { status: bodies.length === 1 ? 500 : 200 });
    },
  });
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body,
    duplex: "half",
  });
  const response = await client.fetch(request, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(bodies, ["hello", "hello"]);
});

test("SigV4Client.fetch caps exponential retry delay", async () => {
  const originalRandom = Math.random;
  const originalSetTimeout = globalThis.setTimeout;
  const delays = [];
  try {
    Math.random = () => 1;
    globalThis.setTimeout = (callback, delay) => {
      delays.push(delay);
      callback();
      return 0;
    };
    const client = lambdaClient({
      retries: 2,
      initialRetryDelayMs: 50,
      maxRetryDelayMs: 7,
      fetch: async () => new Response("retry", { status: 500 }),
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(delays, [7, 7]);
  } finally {
    Math.random = originalRandom;
    globalThis.setTimeout = originalSetTimeout;
  }
});

test("SigV4Client.fetch clamps retry delays to the platform timeout limit", async () => {
  const originalRandom = Math.random;
  const originalSetTimeout = globalThis.setTimeout;
  const delays = [];
  try {
    Math.random = () => 1;
    globalThis.setTimeout = (callback, delay) => {
      delays.push(delay);
      callback();
      return 0;
    };
    const client = lambdaClient({
      retries: 1,
      initialRetryDelayMs: Number.MAX_SAFE_INTEGER,
      maxRetryDelayMs: Number.MAX_SAFE_INTEGER,
      fetch: async () => new Response("retry", { status: 500 }),
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(delays, [2_147_483_647]);
  } finally {
    Math.random = originalRandom;
    globalThis.setTimeout = originalSetTimeout;
  }
});

test("SigV4Client rejects negative retries", () => {
  assert.throws(
    () =>
      lambdaClient({
        retries: -1,
      }),
    /retries must be a non-negative integer/
  );
});

test("SigV4Client.fetch rejects invalid HTTP methods before retry planning", async () => {
  const client = lambdaClient({
    retries: 1,
    fetch: async () => new Response("unreachable"),
  });
  for (const method of [123, Symbol("GET")]) {
    await assert.rejects(
      () =>
        client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          method,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /method must be a valid HTTP token/
    );
  }
});

test("SigV4Client.fetch does not retry non-retryable responses", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 3,
    fetch: async () => {
      calls += 1;
      return new Response("bad request", { status: 400 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 400);
  assert.equal(calls, 1);
});

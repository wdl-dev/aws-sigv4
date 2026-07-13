// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { FIXED_AMZ_DATE, LAMBDA_ENDPOINT, S3_ENDPOINT, lambdaClient, lambdaRequest, s3Client } from "./helpers.js";
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
  let calls = 0;
  const bodies = [];
  const hashes = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      calls += 1;
      bodies.push(await request.clone().text());
      hashes.push(request.headers.get("x-amz-content-sha256"));
      return new Response("ok", { status: calls === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: new Blob(["hello"]),
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(bodies, ["hello", "hello"]);
  assert.deepEqual(hashes, [
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  ]);
});

test("SigV4Client.fetch reuses one prepared byte snapshot across signing attempts", async () => {
  const OriginalRequest = globalThis.Request;
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  const sourceBody = new Uint8Array(4096).fill(0x61);
  const payloadDigestInputs = [];
  const signedRequestBodies = [];
  let calls = 0;

  crypto.subtle.digest = async (algorithm, data) => {
    if (ArrayBuffer.isView(data) && data.byteLength === sourceBody.byteLength) {
      payloadDigestInputs.push(data);
    }
    return originalDigest(algorithm, data);
  };
  globalThis.Request = class RecordingRequest extends OriginalRequest {
    constructor(input, init) {
      if (init?.body instanceof Uint8Array && init.body.byteLength === sourceBody.byteLength) {
        signedRequestBodies.push(init.body);
      }
      super(input, init);
    }
  };

  try {
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
      body: sourceBody,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200);
  } finally {
    globalThis.Request = OriginalRequest;
    crypto.subtle.digest = originalDigest;
  }

  assert.equal(payloadDigestInputs.length, 1);
  assert.equal(signedRequestBodies.length, 2);
  assert.notEqual(payloadDigestInputs[0], sourceBody);
  assert.equal(signedRequestBodies[0], payloadDigestInputs[0]);
  assert.equal(signedRequestBodies[1], payloadDigestInputs[0]);
});

test("SigV4Client.fetch does not retry after a sign override changes the body", async () => {
  const encoder = new TextEncoder();
  const bodies = [];
  const client = s3Client({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      bodies.push(await request.text());
      return new Response("ok", { status: bodies.length === 1 ? 500 : 200 });
    },
  });
  const defaultSign = client.sign;
  client.sign = function changeBodyOnce(input, init) {
    init.body = encoder.encode("changed");
    client.sign = defaultSign;
    return defaultSign.call(this, input, init);
  };

  const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/override-body.bin`, {
    method: "PUT",
    body: encoder.encode("original"),
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 500);
  assert.deepEqual(bodies, ["changed"]);
});

test("SigV4Client.fetch does not retry a stream when sign changes POST to PUT", async () => {
  const transportError = new TypeError("network unavailable");
  const methods = [];
  let fetchCalls = 0;
  const client = s3Client({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      fetchCalls += 1;
      methods.push(request.method);
      assert.equal(await request.text(), "stream-body");
      throw transportError;
    },
  });
  const defaultSign = client.sign;
  client.sign = function signAsPut(input, init) {
    return defaultSign.call(this, input, { ...init, method: "PUT" });
  };
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("stream-body"));
      controller.close();
    },
  });

  await assert.rejects(
    () =>
      client.fetch(`${S3_ENDPOINT}/example-bucket/post-to-put.bin`, {
        method: "POST",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    (error) => error === transportError
  );
  assert.equal(fetchCalls, 1);
  assert.deepEqual(methods, ["PUT"]);
});

test("SigV4Client.fetch does not retry a stream after a POST to PUT hook receives HTTP 500", async () => {
  const methods = [];
  let fetchCalls = 0;
  const client = s3Client({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      fetchCalls += 1;
      methods.push(request.method);
      assert.equal(await request.text(), "stream-body");
      return new Response("retry", { status: 500 });
    },
  });
  const defaultSign = client.sign;
  client.sign = function signAsPut(input, init) {
    return defaultSign.call(this, input, { ...init, method: "PUT" });
  };
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("stream-body"));
      controller.close();
    },
  });

  const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/post-to-put-500.bin`, {
    method: "POST",
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 500);
  assert.equal(fetchCalls, 1);
  assert.deepEqual(methods, ["PUT"]);
});

test("SigV4Client.fetch does not retry target or conditional-header changes from sign hooks", async () => {
  for (const fixture of [
    {
      name: "target",
      apply(signCall, input, init) {
        return {
          input: `${S3_ENDPOINT}/example-bucket/${signCall === 1 ? "first" : "second"}`,
          init,
        };
      },
      observe(request) {
        return new URL(request.url).pathname;
      },
      expected: "/example-bucket/first",
    },
    {
      name: "if-match",
      apply(signCall, input, init) {
        const headers = new Headers(init.headers);
        headers.set("if-match", signCall === 1 ? "one" : "two");
        return { input, init: { ...init, headers } };
      },
      observe(request) {
        return request.headers.get("if-match");
      },
      expected: "one",
    },
  ]) {
    const observed = [];
    let signCalls = 0;
    const client = s3Client({
      retries: 1,
      initialRetryDelayMs: 0,
      fetch: async (request) => {
        observed.push(fixture.observe(request));
        return new Response("retry", { status: 500 });
      },
    });
    const defaultSign = client.sign;
    client.sign = function changeRequestSemantics(input, init) {
      signCalls += 1;
      const changed = fixture.apply(signCalls, input, init);
      return defaultSign.call(this, changed.input, changed.init);
    };

    const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/original`, {
      method: "DELETE",
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 500, fixture.name);
    assert.equal(signCalls, 1, fixture.name);
    assert.deepEqual(observed, [fixture.expected], fixture.name);
  }
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

test("SigV4Client.fetch snapshots mutable unsigned bodies before retrying", async () => {
  const cases = [
    {
      name: "Uint8Array",
      body: new TextEncoder().encode("before"),
      mutate(body) {
        body.fill(120);
      },
      expected: "before",
    },
    {
      name: "URLSearchParams",
      body: new URLSearchParams({ state: "before" }),
      mutate(body) {
        body.set("state", "after");
      },
      expected: "state=before",
    },
  ];
  for (const fixture of cases) {
    const bodies = [];
    const client = s3Client({
      retries: 1,
      initialRetryDelayMs: 0,
      fetch: async (request) => {
        bodies.push(await request.clone().text());
        fixture.mutate(fixture.body);
        return new Response("ok", { status: bodies.length === 1 ? 500 : 200 });
      },
    });
    const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/replay-${fixture.name}`, {
      method: "PUT",
      body: fixture.body,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200, fixture.name);
    assert.deepEqual(bodies, [fixture.expected, fixture.expected], fixture.name);
  }
});

test("SigV4Client.fetch replays unsigned Blob bodies with their content-type signed", async () => {
  const bodies = [];
  const client = s3Client({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      bodies.push(await request.text());
      assert.equal(request.headers.get("content-type"), "text/plain");
      assert.match(
        request.headers.get("authorization") || "",
        /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/
      );
      return new Response("ok", { status: bodies.length === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/blob-replay.txt`, {
    method: "PUT",
    body: new Blob(["stable"], { type: "text/plain" }),
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(bodies, ["stable", "stable"]);
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

test("SigV4Client.fetch applies full jitter to exponential retry delays", async () => {
  const originalRandom = Math.random;
  const originalSetTimeout = globalThis.setTimeout;
  const delays = [];
  try {
    Math.random = () => 0.25;
    globalThis.setTimeout = (callback, delay) => {
      delays.push(delay);
      callback();
      return 0;
    };
    const client = lambdaClient({
      retries: 3,
      initialRetryDelayMs: 40,
      maxRetryDelayMs: 1_000,
      fetch: async () => new Response("retry", { status: 500 }),
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 500);
    assert.deepEqual(delays, [10, 20, 40]);
  } finally {
    Math.random = originalRandom;
    globalThis.setTimeout = originalSetTimeout;
  }
});

test("SigV4Client.fetch applies full jitter after transient fetch rejections", async () => {
  const originalRandom = Math.random;
  const originalSetTimeout = globalThis.setTimeout;
  const delays = [];
  let calls = 0;
  try {
    Math.random = () => 0.25;
    globalThis.setTimeout = (callback, delay) => {
      delays.push(delay);
      callback();
      return 0;
    };
    const client = lambdaClient({
      retries: 3,
      initialRetryDelayMs: 40,
      maxRetryDelayMs: 1_000,
      fetch: async () => {
        calls += 1;
        throw new TypeError("socket reset");
      },
    });
    await assert.rejects(
      () =>
        client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /socket reset/
    );
    assert.equal(calls, 4);
    assert.deepEqual(delays, [10, 20, 40]);
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

test("SigV4Client rejects retries outside the safe integer range", () => {
  for (const retries of [Number.MAX_SAFE_INTEGER + 1, Infinity, 1.5]) {
    assert.throws(
      () => lambdaClient({ retries }),
      /retries must be a non-negative integer within the safe integer range/
    );
  }
});

test("SigV4Client rejects invalid retry delay bounds", () => {
  for (const name of ["initialRetryDelayMs", "maxRetryDelayMs"]) {
    for (const value of [-1, Number.NaN, Infinity]) {
      assert.throws(() => lambdaClient({ [name]: value }), new RegExp(`${name} must be a non-negative finite number`));
    }
  }
});

test("SigV4Client rejects null retry configuration", () => {
  const expectations = {
    retries: /retries must be a non-negative integer within the safe integer range/,
    initialRetryDelayMs: /initialRetryDelayMs must be a non-negative finite number/,
    maxRetryDelayMs: /maxRetryDelayMs must be a non-negative finite number/,
  };
  for (const [name, expected] of Object.entries(expectations)) {
    assert.throws(() => lambdaClient({ [name]: null }), expected);
  }
});

test("SigV4Client.fetch preserves an explicit null abort reason", async () => {
  const controller = new AbortController();
  controller.abort(null);
  let caught = Symbol("not caught");
  try {
    await lambdaClient().fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signal: controller.signal,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
  } catch (err) {
    caught = err;
  }
  assert.equal(caught, null);
});

test("SigV4Client.fetch aborts while retry response cancellation is stalled", { timeout: 2_000 }, async () => {
  let cancelStartedResolve;
  const cancelStarted = new Promise((resolve) => {
    cancelStartedResolve = resolve;
  });
  const controller = new AbortController();
  const reason = { code: "stop-response-cancellation" };
  let fetchCalls = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      fetchCalls += 1;
      return new Response(
        new ReadableStream({
          cancel() {
            cancelStartedResolve();
            return new Promise(() => {});
          },
        }),
        { status: 500 }
      );
    },
  });
  const pending = client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signal: controller.signal,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  await cancelStarted;
  controller.abort(reason);
  let caught;
  try {
    await pending;
  } catch (err) {
    caught = err;
  }
  assert.equal(caught, reason);
  assert.equal(fetchCalls, 1);
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

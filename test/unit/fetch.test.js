// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { SigV4Client } from "../../dist/index.js";
import {
  ACCESS_KEY_ID,
  EXECUTE_API_ENDPOINT,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  SECRET_ACCESS_KEY,
  SESSION_TOKEN,
  assertFetchRejectsBeforeBody,
  executeApiClient,
  helloStream,
  lambdaClient,
  s3Client,
} from "./helpers.js";

test("SigV4Client.fetch binds the default global fetch", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = function fetchWithGlobalThisCheck() {
      assert.equal(this, globalThis);
      return Promise.resolve(new Response("ok"));
    };
    const client = lambdaClient({
      retries: 0,
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SigV4Client.fetch binds custom global fetch functions", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = function fetchWithGlobalThisCheck() {
      assert.equal(this, globalThis);
      return Promise.resolve(new Response("ok"));
    };
    const client = lambdaClient({
      fetch: globalThis.fetch,
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SigV4Client.fetch does not bind unrelated custom fetch functions", async () => {
  let observedThis;
  const client = lambdaClient({
    fetch: function customFetch() {
      observedThis = this;
      return Promise.resolve(new Response("ok"));
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(observedThis, undefined);
});

test("SigV4Client.fetch signs each retry attempt with the current time", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-06-16T01:02:03Z") });
  const seen = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      seen.push({
        authorization: request.headers.get("authorization"),
        amzDate: request.headers.get("x-amz-date"),
      });
      t.mock.timers.setTime(new Date("2026-06-16T01:02:04Z").getTime());
      return new Response("ok", { status: seen.length === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: "{}",
  });
  assert.equal(response.status, 200);
  assert.equal(seen.length, 2);
  assert.deepEqual(
    seen.map(({ amzDate }) => amzDate),
    ["20260616T010203Z", "20260616T010204Z"]
  );
  assert.notEqual(seen[0].authorization, seen[1].authorization);
});

test("SigV4Client.fetch calls sign overrides once and disables automatic retries", async () => {
  for (const overrideKind of ["subclass", "instance"]) {
    let calls = 0;
    let signCalls = 0;
    const options = {
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET_ACCESS_KEY,
      service: "lambda",
      region: "ap-northeast-1",
      retries: 1,
      initialRetryDelayMs: 0,
      fetch: async () => {
        calls += 1;
        return new Response("ok", { status: calls === 1 ? 500 : 200 });
      },
    };
    let client;
    if (overrideKind === "subclass") {
      class HookedSigV4Client extends SigV4Client {
        sign(input, init) {
          signCalls += 1;
          return super.sign(input, init);
        }
      }
      client = new HookedSigV4Client(options);
    } else {
      client = new SigV4Client(options);
      const sign = client.sign;
      client.sign = function wrappedSign(input, init) {
        signCalls += 1;
        return sign.call(this, input, init);
      };
    }

    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method: "PUT",
      body: "{}",
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 500, overrideKind);
    assert.equal(calls, 1, overrideKind);
    assert.equal(signCalls, 1, overrideKind);
  }
});

test(
  "SigV4Client.fetch rejects redirect modes and cancels hook bodies before transport",
  { timeout: 2_000 },
  async () => {
    let fetchCalls = 0;
    const tracked = trackedCancellationStream();
    const client = s3Client({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    const defaultSign = client.sign;
    client.sign = async function signWithFollowRedirect(input, init) {
      const signed = await defaultSign.call(this, input, init);
      return new Request(signed, { redirect: "follow" });
    };

    await assert.rejects(
      () =>
        client.fetch(`${S3_ENDPOINT}/example-bucket/redirect-hook`, {
          method: "PUT",
          body: tracked.body,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /SigV4Client\.sign\(\) must return a Request with redirect: "manual"/
    );
    await tracked.cancelled;
    assert.equal(fetchCalls, 0);
    assert.equal(tracked.cancelCalls(), 1);
    assert.match(tracked.cancelReason()?.message || "", /redirect: "manual"/);
  }
);

test(
  "SigV4Client.fetch rejects no-cors modes and cancels hook bodies before transport",
  { timeout: 2_000 },
  async () => {
    let fetchCalls = 0;
    const tracked = trackedCancellationStream();
    const client = s3Client({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    const defaultSign = client.sign;
    client.sign = async function signWithNoCorsMode(input, init) {
      const signed = await defaultSign.call(this, input, init);
      Object.defineProperty(signed, "mode", { value: "no-cors" });
      return signed;
    };

    await assert.rejects(
      () =>
        client.fetch(`${S3_ENDPOINT}/example-bucket/no-cors-hook`, {
          method: "POST",
          body: tracked.body,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /cannot sign requests with mode "no-cors"/
    );
    await tracked.cancelled;
    assert.equal(fetchCalls, 0);
    assert.equal(tracked.cancelCalls(), 1);
    assert.match(tracked.cancelReason()?.message || "", /mode "no-cors"/);
  }
);

test("SigV4Client.fetch preserves the source signal when a sign override drops it", async () => {
  const controller = new AbortController();
  const reason = { code: "source-aborted" };
  let transportSignal;
  let releaseTransport;
  let transportStartedResolve;
  const transportStarted = new Promise((resolve) => {
    transportStartedResolve = resolve;
  });
  const transportRelease = new Promise((resolve) => {
    releaseTransport = resolve;
  });
  const client = lambdaClient({
    fetch: async (request) => {
      transportSignal = request.signal;
      transportStartedResolve();
      await transportRelease;
      if (request.signal.aborted) {
        throw request.signal.reason;
      }
      return new Response("unexpected");
    },
  });
  const defaultSign = client.sign;
  client.sign = async function signWithoutSourceSignal(input, init) {
    const signed = await defaultSign.call(this, input, init);
    return new Request(signed, { signal: null });
  };

  const pending = client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signal: controller.signal,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  await transportStarted;
  controller.abort(reason);
  releaseTransport();
  await assert.rejects(pending, (error) => error === reason);
  assert.equal(transportSignal.aborted, true);
  assert.equal(transportSignal.reason, reason);
});

test(
  "SigV4Client.fetch cancels hook bodies when the source signal aborts before transport",
  { timeout: 2_000 },
  async () => {
    const controller = new AbortController();
    const reason = { code: "abort-before-transport" };
    const tracked = trackedCancellationStream();
    let fetchCalls = 0;
    const client = s3Client({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    const defaultSign = client.sign;
    client.sign = async function abortAfterSigning(input, init) {
      const signed = await defaultSign.call(this, input, init);
      controller.abort(reason);
      return new Request(signed, { signal: null });
    };

    await assert.rejects(
      () =>
        client.fetch(`${S3_ENDPOINT}/example-bucket/aborted-hook`, {
          method: "PUT",
          body: tracked.body,
          signal: controller.signal,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      (error) => error === reason
    );
    await tracked.cancelled;
    assert.equal(fetchCalls, 0);
    assert.equal(tracked.cancelCalls(), 1);
    assert.equal(tracked.cancelReason(), reason);
  }
);

test(
  "SigV4Client.fetch cancels hook bodies when the returned signal is already aborted",
  { timeout: 2_000 },
  async () => {
    const controller = new AbortController();
    const reason = { code: "hook-aborted" };
    const tracked = trackedCancellationStream();
    let fetchCalls = 0;
    const client = s3Client({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    const defaultSign = client.sign;
    client.sign = async function returnAbortedRequest(input, init) {
      const signed = await defaultSign.call(this, input, init);
      controller.abort(reason);
      return new Request(signed, { signal: controller.signal });
    };

    await assert.rejects(
      () =>
        client.fetch(`${S3_ENDPOINT}/example-bucket/hook-aborted`, {
          method: "PUT",
          body: tracked.body,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      (error) => error === reason
    );
    await tracked.cancelled;
    assert.equal(fetchCalls, 0);
    assert.equal(tracked.cancelCalls(), 1);
    assert.equal(tracked.cancelReason(), reason);
  }
);

test("SigV4Client.fetch snapshots URL objects across asynchronous work and retries", async () => {
  const originalUrl = `${LAMBDA_ENDPOINT}/2025-09-09/original`;
  const url = new URL(originalUrl);
  const seen = [];
  const client = lambdaClient({
    sessionToken: SESSION_TOKEN,
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      seen.push({
        url: request.url,
        authorization: request.headers.get("authorization"),
        sessionToken: request.headers.get("x-amz-security-token"),
      });
      url.href = `${LAMBDA_ENDPOINT}/2025-09-09/changed-between-attempts`;
      return new Response("ok", { status: seen.length === 1 ? 500 : 200 });
    },
  });
  const pending = client.fetch(url, {
    method: "PUT",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  url.href = "https://second.example/changed-after-call";
  const response = await pending;
  assert.equal(response.status, 200);
  assert.deepEqual(
    seen.map(({ url: value }) => value),
    [originalUrl, originalUrl]
  );
  assert.ok(seen.every(({ authorization }) => authorization?.startsWith("AWS4-HMAC-SHA256 ")));
  assert.ok(seen.every(({ sessionToken }) => sessionToken === SESSION_TOKEN));
});

test("SigV4Client.fetch snapshots Request headers before asynchronous signing", async () => {
  let fetched;
  const client = lambdaClient({
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const input = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: { "x-amz-meta-original": "yes" },
  });
  const pending = client.fetch(input, { signing: { signingDate: FIXED_AMZ_DATE } });
  input.headers.set("x-amz-meta-late", "must-not-leak");
  const response = await pending;
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-meta-original"), "yes");
  assert.equal(fetched.headers.get("x-amz-meta-late"), null);
  assert.match(fetched.headers.get("authorization") || "", /x-amz-meta-original/);
  assert.doesNotMatch(fetched.headers.get("authorization") || "", /x-amz-meta-late/);
});

test('SigV4Client.fetch rejects transports that follow redirect: "manual"', async () => {
  const client = lambdaClient({
    fetch: async () => {
      const response = new Response("followed");
      Object.defineProperty(response, "redirected", { value: true });
      return response;
    },
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        redirect: "manual",
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /custom transport followed a redirect/
  );
});

test("SigV4Client.fetch uses portable manual transport for redirect policies", async () => {
  const redirects = [];
  const client = lambdaClient({
    fetch: async (request) => {
      redirects.push(request.redirect);
      return new Response("ok");
    },
  });
  await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    redirect: "manual",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    redirect: "error",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`);
  await client.fetch(request, { signing: { signingDate: FIXED_AMZ_DATE } });
  const manualRequest = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, { redirect: "manual" });
  await client.fetch(manualRequest, { signing: { signingDate: FIXED_AMZ_DATE } });
  assert.deepEqual(redirects, ["manual", "manual", "manual", "manual", "manual"]);
});

test("SigV4Client.fetch rejects redirect responses by default and returns them in manual mode", async () => {
  const client = lambdaClient({
    fetch: async () => new Response("redirect", { status: 302, headers: { location: "/next" } }),
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /received a redirect response/
  );
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    redirect: "manual",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "/next");
});

test("SigV4Client.fetch works when the runtime rejects Request redirect error", async () => {
  const OriginalRequest = globalThis.Request;
  try {
    globalThis.Request = class WorkerdRequest extends OriginalRequest {
      constructor(input, init) {
        if (init?.redirect === "error") {
          throw new TypeError('Invalid redirect value; "error" is unsupported');
        }
        super(input, init);
      }
    };
    let observedRedirect;
    const client = lambdaClient({
      fetch: async (request) => {
        observedRedirect = request.redirect;
        return new Response("ok");
      },
    });
    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200);
    assert.equal(observedRedirect, "manual");
  } finally {
    globalThis.Request = OriginalRequest;
  }
});

test("SigV4Client.fetch rejects redirect follow before consuming request bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        redirect: "follow",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    /does not allow redirect: "follow"/
  );
});

test("SigV4Client.fetch rejects invalid redirect values before consuming request bodies", async () => {
  for (const redirect of [null, "bogus"]) {
    await assertFetchRejectsBeforeBody(
      {},
      (body) => ({
        init: {
          method: "PUT",
          redirect,
          body,
          signing: { signingDate: FIXED_AMZ_DATE },
        },
      }),
      /redirect must be "error" or "manual"/
    );
  }
});

test("SigV4Client rejects no-cors mode before consuming request bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "POST",
        mode: "no-cors",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    /cannot sign requests with mode "no-cors"/
  );
  const client = lambdaClient();
  await assert.rejects(
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, { mode: "no-cors" }),
    /cannot sign requests with mode "no-cors"/
  );
});

test("SigV4Client rejects partially consumed Request bodies", async () => {
  for (const operation of ["sign", "fetch"]) {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("first"));
        controller.enqueue(new TextEncoder().encode("second"));
        controller.close();
      },
    });
    const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method: "POST",
      body,
      duplex: "half",
    });
    const reader = request.body.getReader();
    await reader.read();
    reader.releaseLock();
    let fetchCalls = 0;
    const client = lambdaClient({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    await assert.rejects(
      () => client[operation](request, { signing: { signingDate: FIXED_AMZ_DATE } }),
      /Request body has already been used/
    );
    assert.equal(fetchCalls, 0, operation);
  }
});

test("Request body null overrides inherit the input body", async () => {
  const url = `${LAMBDA_ENDPOINT}/2025-09-09/microvms`;
  const signed = await lambdaClient().sign(new Request(url, { method: "POST", body: "signed-body" }), {
    body: null,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(await signed.text(), "signed-body");

  let fetchedBody;
  const client = lambdaClient({
    fetch: async (request) => {
      fetchedBody = await request.text();
      return new Response("ok");
    },
  });
  await client.fetch(new Request(url, { method: "POST", body: "fetched-body" }), {
    body: null,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(fetchedBody, "fetched-body");
});

test("SigV4Client detects signed headers removed by runtime Request guards", async () => {
  const OriginalRequest = globalThis.Request;
  try {
    for (const [removedHeader, message] of [
      ["authorization", /runtime removed or rewrote the authorization header/],
      ["x-amz-meta-color", /runtime removed or rewrote the signed x-amz-meta-color header/],
    ]) {
      globalThis.Request = class GuardedRequest extends OriginalRequest {
        constructor(input, init) {
          super(input, init);
          this.headers.delete(removedHeader);
        }
      };
      const client = lambdaClient();
      await assert.rejects(
        () =>
          client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
            headers: { "x-amz-meta-color": "blue" },
            signing: { signingDate: FIXED_AMZ_DATE },
          }),
        message
      );
    }
  } finally {
    globalThis.Request = OriginalRequest;
  }
});

test("SigV4Client.fetch rejects non-printable signed header values before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        headers: {
          "x-amz-meta-filename": "Résumé.pdf",
        },
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    {
      name: "TypeError",
      message: /x-amz-meta-filename header value must contain only printable ASCII characters/,
    }
  );
});

test("SigV4Client.fetch ignores overwritten x-amz-date during retry preparation", async () => {
  let fetched;
  const body = helloStream();
  const client = lambdaClient({
    retries: 1,
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: {
      "x-amz-date": "café",
    },
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-date"), FIXED_AMZ_DATE);
});

test("SigV4Client.fetch validates caller x-amz-security-token headers without client tokens", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        headers: {
          "x-amz-security-token": "tokén",
        },
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    {
      name: "TypeError",
      message: /x-amz-security-token header value must contain only printable ASCII characters/,
    }
  );
});

test("SigV4Client.fetch ignores overwritten x-amz-security-token headers with client tokens", async () => {
  let fetched;
  const body = helloStream();
  const client = lambdaClient({
    sessionToken: SESSION_TOKEN,
    retries: 1,
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: {
      "x-amz-security-token": "tokén",
    },
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-security-token"), SESSION_TOKEN);
});

test("SigV4Client.fetch respects client-level unsignableHeaders during retry preparation", async () => {
  let fetched;
  const body = helloStream();
  const client = lambdaClient({
    retries: 1,
    unsignableHeaders: ["x-debug-only"],
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: {
      "x-debug-only": "Résumé.pdf",
    },
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.doesNotMatch(fetched.headers.get("authorization") || "", /x-debug-only/);
});

test("SigV4Client.fetch lets per-request signAllHeaders override client-level signAllHeaders", async () => {
  let fetched;
  const body = helloStream();
  const client = lambdaClient({
    retries: 1,
    signAllHeaders: true,
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: {
      "user-agent": "Résumé.pdf",
    },
    body,
    signing: { signingDate: FIXED_AMZ_DATE, signAllHeaders: false },
  });
  assert.equal(response.status, 200);
  assert.doesNotMatch(fetched.headers.get("authorization") || "", /user-agent/);
});

test("SigV4Client.fetch respects client-level signAllHeaders during retry preparation", async () => {
  await assertFetchRejectsBeforeBody(
    { signAllHeaders: true },
    (body) => ({
      init: {
        method: "PUT",
        headers: {
          "user-agent": "Résumé.pdf",
        },
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    {
      name: "TypeError",
      message: /user-agent header value must contain only printable ASCII characters/,
    }
  );
});

test("SigV4Client.fetch rejects invalid signingDate before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        body,
        signing: { signingDate: "garbage" },
      },
    }),
    /signingDate must be a valid Date/
  );
});

test("SigV4Client.fetch captures Date signingDate before buffering retry bodies", async () => {
  let fetched;
  const signingDate = new Date("2026-06-16T01:02:03.000Z");
  class TimeChangingBlob extends Blob {
    async arrayBuffer() {
      signingDate.setTime(Date.UTC(2027, 0, 1, 0, 0, 0));
      return super.arrayBuffer();
    }
  }
  const client = lambdaClient({
    retries: 1,
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: new TimeChangingBlob(["hello"]),
    signing: { signingDate },
  });
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-date"), FIXED_AMZ_DATE);
});

test("SigV4Client.fetch rejects invalid per-request service before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        body,
        signing: { service: "lambda test", signingDate: FIXED_AMZ_DATE },
      },
    }),
    /init\.signing\.service must not contain whitespace/
  );
});

test("SigV4Client.fetch rejects empty payload hash headers before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      init: {
        method: "PUT",
        headers: {
          "x-amz-content-sha256": "",
        },
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    /x-amz-content-sha256 must not be empty/
  );
});

test("SigV4Client.fetch rejects invalid UTF-16 URLs before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => ({
      input: `${LAMBDA_ENDPOINT}/2025-09-09/\ud83d`,
      init: {
        method: "PUT",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      },
    }),
    /url must not contain invalid UTF-16/
  );
});

test("SigV4Client.fetch validates signed headers merged from Request inputs before buffering retry bodies", async () => {
  await assertFetchRejectsBeforeBody(
    {},
    (body) => {
      const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "PUT",
        headers: {
          "x-amz-meta-filename": "Résumé.pdf",
        },
        body,
        duplex: "half",
      });
      return {
        input: request,
        init: {
          signing: { signingDate: FIXED_AMZ_DATE },
        },
        assertBodyReadable: async () => {
          assert.equal(await request.text(), "hello");
        },
      };
    },
    {
      name: "TypeError",
      message: /x-amz-meta-filename header value must contain only printable ASCII characters/,
    }
  );
});

test("SigV4Client.fetch uses the same payload hash headers as sign()", async () => {
  let fetched;
  const client = lambdaClient({
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const init = {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  };
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-content-sha256"), signed.headers.get("x-amz-content-sha256"));
  assert.equal(fetched.headers.get("authorization"), signed.headers.get("authorization"));
});

test("SigV4Client.fetch preserves one-shot headers after retry preparation", async () => {
  let fetched;
  const contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const client = s3Client({
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${S3_ENDPOINT}/example-bucket/objects/headers.txt`, {
    method: "GET",
    headers: new Map([
      ["x-amz-content-sha256", contentHash],
      ["x-amz-meta-color", "blue"],
    ]).entries(),
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("x-amz-content-sha256"), contentHash);
  assert.equal(fetched.headers.get("x-amz-meta-color"), "blue");
  assert.match(fetched.headers.get("authorization") || "", /x-amz-meta-color/);
});

test("SigV4Client.fetch honors doubleUrlEncode during signing", async () => {
  let fetched;
  const client = executeApiClient({
    doubleUrlEncode: true,
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const response = await client.fetch(`${EXECUTE_API_ENDPOINT}/prod/my+folder/file.txt`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(
    fetched.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=7ba4625b596ebe31fa2c3f7a79b2f2c8eadc98ecea15a82ec819d15b6efbab2a"
  );
});

test("SigV4Client.fetch preserves Request content-type when init overrides body", async () => {
  let fetched;
  const client = lambdaClient({
    fetch: async (request) => {
      fetched = request;
      return new Response("ok");
    },
  });
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    headers: {
      "content-type": "application/json",
    },
  });
  const init = {
    method: "PUT",
    body: JSON.stringify({ a: 1 }),
    signing: { signingDate: FIXED_AMZ_DATE },
  };
  const signed = await client.sign(request, init);
  const response = await client.fetch(request, init);
  assert.equal(response.status, 200);
  assert.equal(fetched.headers.get("content-type"), "application/json");
  assert.equal(fetched.headers.get("authorization"), signed.headers.get("authorization"));
});

function trackedCancellationStream() {
  let calls = 0;
  let reason;
  let cancelledResolve;
  const cancelled = new Promise((resolve) => {
    cancelledResolve = resolve;
  });
  const body = new ReadableStream({
    cancel(value) {
      calls += 1;
      reason = value;
      cancelledResolve();
    },
  });
  return {
    body,
    cancelled,
    cancelCalls: () => calls,
    cancelReason: () => reason,
  };
}

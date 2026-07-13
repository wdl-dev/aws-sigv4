// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { SigV4Client } from "../../dist/index.js";
import { ACCESS_KEY_ID, FIXED_AMZ_DATE, LAMBDA_ENDPOINT, SECRET_ACCESS_KEY, lambdaClient } from "./helpers.js";

test("SigV4Client.fetch binds the default global fetch", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = function fetchWithGlobalThisCheck() {
      assert.equal(this, globalThis);
      return Promise.resolve(new Response("ok"));
    };
    const client = lambdaClient({ retries: 0 });
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
    const client = lambdaClient({ fetch: globalThis.fetch });
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

test("SigV4Client.fetch ignores sign overrides and retains automatic retries", async () => {
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
        sign() {
          signCalls += 1;
          throw new Error("fetch must not call an overridden sign method");
        }
      }
      client = new HookedSigV4Client(options);
    } else {
      client = new SigV4Client(options);
      client.sign = function wrappedSign() {
        signCalls += 1;
        throw new Error("fetch must not call an overridden sign method");
      };
    }

    const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method: "PUT",
      body: "{}",
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(response.status, 200, overrideKind);
    assert.equal(calls, 2, overrideKind);
    assert.equal(signCalls, 0, overrideKind);
  }
});

test("SigV4Client.fetch preserves the source signal through transport", async () => {
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

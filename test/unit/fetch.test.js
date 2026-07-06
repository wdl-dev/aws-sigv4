// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  EXECUTE_API_ENDPOINT,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
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

test("SigV4Client.fetch signs each retry attempt", async () => {
  const seen = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      seen.push(request.headers.get("authorization"));
      return new Response("ok", { status: seen.length === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(seen.length, 2);
  assert.equal(typeof seen[0], "string");
  assert.equal(typeof seen[1], "string");
});

test("SigV4Client.fetch rejects non-printable signed header values before retry body preparation", async () => {
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

test("SigV4Client.fetch rejects invalid signingDate before retry body preparation", async () => {
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

test("SigV4Client.fetch captures Date signingDate before retry body preparation", async () => {
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

test("SigV4Client.fetch rejects invalid per-request service before retry body preparation", async () => {
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

test("SigV4Client.fetch rejects empty payload hash headers before retry body preparation", async () => {
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

test("SigV4Client.fetch rejects invalid UTF-16 URLs before retry body preparation", async () => {
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

test("SigV4Client.fetch validates signed headers merged from Request inputs before retry body preparation", async () => {
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

test("SigV4Client.fetch matches sign() payload hash headers", async () => {
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

test("SigV4Client.fetch passes doubleUrlEncode through request preparation", async () => {
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

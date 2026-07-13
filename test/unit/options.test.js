// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { signAwsRequest } from "../../dist/index.js";

import {
  ACCESS_KEY_ID,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  SECRET_ACCESS_KEY,
  SESSION_TOKEN,
  lambdaClient,
  lambdaRequest,
  s3Client,
  s3Request,
} from "./helpers.js";

test("SigV4Client rejects non-function fetch options", () => {
  for (const fetch of [null, false, 0]) {
    assert.throws(() => lambdaClient({ fetch }), /fetch must be a function/);
  }
});

test("SigV4Client keeps credential and transport state out of enumerable properties", async () => {
  const client = lambdaClient({ sessionToken: SESSION_TOKEN });
  assert.deepEqual(Object.keys(client), []);
  assert.deepEqual({ ...client }, {});
  assert.equal(JSON.stringify(client), "{}");
  for (const name of ["accessKeyId", "secretAccessKey", "sessionToken", "cache", "fetchFn"]) {
    assert.equal(Object.hasOwn(client, name), false, name);
  }

  const before = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  client.secretAccessKey = "attacker-controlled-shadow";
  const after = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(after.headers.get("authorization"), before.headers.get("authorization"));
});

test("signAllHeaders signs otherwise volatile headers", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "user-agent": "fixture-agent",
    },
    signAllHeaders: true,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;user-agent;x-amz-date, Signature=dd02aa3718e547262492eea7c2616bb0b1488fab5f4cd524425c656189d5a9f4"
  );
});

test("signAllHeaders still excludes existing authorization headers", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      authorization: "Bearer stale",
      "user-agent": "fixture-agent",
    },
    signAllHeaders: true,
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.match(authorization, /SignedHeaders=host;user-agent;x-amz-date/);
  assert.doesNotMatch(authorization, /SignedHeaders=.*authorization/);
});

test("signAllHeaders respects explicit unsignableHeaders", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "user-agent": "fixture-agent",
      "x-debug-only": "skip-me",
    },
    signAllHeaders: true,
    unsignableHeaders: ["x-debug-only"],
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.match(authorization, /SignedHeaders=host;user-agent;x-amz-date/);
  assert.doesNotMatch(authorization, /x-debug-only/);
});

test("default signing excludes hop-by-hop headers", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "accept-encoding": "gzip",
      connection: "keep-alive",
      "content-length": "123",
      expect: "100-continue",
      "keep-alive": "timeout=5",
      "presigned-expires": "60",
      "proxy-authenticate": "Basic",
      "proxy-authorization": "Basic stale",
      te: "trailers",
      trailer: "x-debug",
      "transfer-encoding": "chunked",
      upgrade: "websocket",
      "x-amzn-trace-id": "Root=1-abcdef12-345678901234567890abcdef",
      "user-agent": "fixture-agent",
    },
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482"
  );
});

test("sign(Request) reads request bodies even without x-amz-content-sha256", async () => {
  const client = lambdaClient();
  const url = `${LAMBDA_ENDPOINT}/2025-09-09/microvms`;
  const signedRequest = await client.sign(
    new Request(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }),
    { signing: { signingDate: FIXED_AMZ_DATE } }
  );
  const signedExplicit = await lambdaRequest({
    method: "POST",
    url,
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(signedRequest.headers.get("authorization"), signedExplicit.headers.get("authorization"));
});

test("sign(Request, init) merges request headers with init headers", async () => {
  const client = lambdaClient();
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-base": "base",
    },
    body: "{}",
  });
  const signed = await client.sign(request, {
    headers: {
      "x-extra": "extra",
    },
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(signed.headers.get("content-type"), "application/json");
  assert.equal(signed.headers.get("x-base"), "base");
  assert.equal(signed.headers.get("x-extra"), "extra");
  assert.match(
    signed.headers.get("authorization") || "",
    /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-base;x-extra/
  );
});

test("SigV4Client uses per-request region overrides", async () => {
  const client = lambdaClient({ region: "us-east-1" });
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: {
      region: "ap-northeast-1",
      signingDate: FIXED_AMZ_DATE,
    },
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482"
  );
});

test("SigV4Client uses per-request service overrides for signing and payload defaults", async () => {
  const client = s3Client({ region: "ap-northeast-1" });
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: "{}",
    signing: {
      service: "lambda",
      signingDate: FIXED_AMZ_DATE,
    },
  });
  assert.equal(
    signed.headers.get("x-amz-content-sha256"),
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
  );
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=de89cd04f1fd244964d976e79a614522733e20fdc2dbebc51bdcb56714f50fac"
  );
});

test("SigV4Client rejects GET and HEAD bodies", async () => {
  const client = lambdaClient();
  for (const method of ["GET", "HEAD"]) {
    await assert.rejects(
      () =>
        client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          method,
          body: "{}",
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /GET and HEAD requests with a body require signAwsRequest/
    );
  }
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    body: "{}",
  });
  assert.equal(signed.method, "GET");
  assert.equal(await new Response(signed.body).text(), "{}");
});

test("signing defaults to GET without a body and POST with a body", async () => {
  const url = `${LAMBDA_ENDPOINT}/2025-09-09/microvms`;
  const lowerGet = await lambdaRequest({ url });
  const lowerPost = await lambdaRequest({ url, body: "{}" });
  assert.equal(lowerGet.method, "GET");
  assert.equal(lowerPost.method, "POST");

  const observedFetchMethods = [];
  const client = lambdaClient({
    fetch: async (request) => {
      observedFetchMethods.push(request.method);
      return new Response("ok");
    },
  });
  const clientGet = await client.sign(url, { signing: { signingDate: FIXED_AMZ_DATE } });
  const clientPost = await client.sign(url, {
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(clientGet.method, "GET");
  assert.equal(clientPost.method, "POST");

  await client.fetch(url, { signing: { signingDate: FIXED_AMZ_DATE } });
  await client.fetch(url, {
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.deepEqual(observedFetchMethods, ["GET", "POST"]);
});

test("sign(Request) preserves request transport options", async () => {
  const client = lambdaClient();
  const controller = new AbortController();
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    credentials: "include",
    integrity: "sha256-test",
    redirect: "manual",
    signal: controller.signal,
  });
  const signed = await client.sign(request, {
    signal: undefined,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(signed.credentials, "include");
  assert.equal(signed.integrity, "sha256-test");
  assert.equal(signed.redirect, "manual");
  assert.equal(signed.signal.aborted, false);
  controller.abort();
  assert.equal(signed.signal.aborted, true);
});

test("sign(Request) preserves stream duplex option", async () => {
  const client = lambdaClient({ unsignedPayload: true });
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.close();
      },
    }),
    duplex: "half",
  });
  const signed = await client.sign(request, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(signed.duplex, "half");
});

test("unsignableHeaders adds to the default volatile header set", async () => {
  const signed = await lambdaRequest({
    method: "POST",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "content-type": "application/json",
      "x-debug-only": "skip-me",
    },
    body: "{}",
    unsignableHeaders: ["x-debug-only"],
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.match(authorization, /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);
  assert.doesNotMatch(authorization, /x-debug-only/);
});

test("unsignableHeaders rejects SigV4 core headers", async () => {
  for (const header of ["host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"]) {
    await assert.rejects(
      () =>
        s3Request({
          method: "PUT",
          url: `${S3_ENDPOINT}/example-bucket/core-headers.txt`,
          body: "hello",
          sessionToken: SESSION_TOKEN,
          unsignableHeaders: [header],
        }),
      new RegExp(`mandatory signed header ${header}`)
    );
  }
});

test("unsignableHeaders rejects request x-amz headers and S3 content-md5", async () => {
  for (const fixture of [
    {
      request: () =>
        lambdaRequest({
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
          headers: { "x-amz-meta-owner": "alice" },
          unsignableHeaders: ["x-amz-meta-owner"],
        }),
      header: "x-amz-meta-owner",
    },
    {
      request: () =>
        s3Request({
          method: "PUT",
          url: `${S3_ENDPOINT}/example-bucket/checksum.txt`,
          headers: { "x-amz-checksum-sha256": "checksum-base64" },
          body: "hello",
          unsignableHeaders: ["x-amz-checksum-sha256"],
        }),
      header: "x-amz-checksum-sha256",
    },
    {
      request: () =>
        s3Request({
          method: "PUT",
          url: `${S3_ENDPOINT}/example-bucket/content-md5.txt`,
          headers: { "content-md5": "CY9rzUYh03PK3k6DJie09g==" },
          body: "hello",
          unsignableHeaders: ["content-md5"],
        }),
      header: "content-md5",
    },
  ]) {
    await assert.rejects(fixture.request, new RegExp(`mandatory signed header ${fixture.header}`));
  }
});

test("unsignableHeaders rejects string inputs", async () => {
  const message = /unsignableHeaders must be an iterable of header names/;
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        unsignableHeaders: "x-debug-only",
      }),
    message
  );
  assert.throws(() => lambdaClient({ unsignableHeaders: "x-debug-only" }), message);
  const client = lambdaClient();
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          signingDate: FIXED_AMZ_DATE,
          unsignableHeaders: "x-debug-only",
        },
      }),
    message
  );
});

test("unsignableHeaders rejects null inputs", async () => {
  const message = /unsignableHeaders must be an iterable of header names/;
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        unsignableHeaders: null,
      }),
    message
  );
  assert.throws(() => lambdaClient({ unsignableHeaders: null }), message);
  const client = lambdaClient();
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          signingDate: FIXED_AMZ_DATE,
          unsignableHeaders: null,
        },
      }),
    /init\.signing\.unsignableHeaders must be an iterable of header names/
  );
});

test("SigV4Client snapshots unsignableHeaders iterables", async () => {
  function* headersToSkip() {
    yield "x-debug-only";
  }
  const client = lambdaClient({
    unsignableHeaders: headersToSkip(),
  });
  const init = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-debug-only": "skip-me",
    },
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  };
  const first = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  const second = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  assert.equal(first.headers.get("authorization"), second.headers.get("authorization"));
  assert.doesNotMatch(second.headers.get("authorization") || "", /x-debug-only/);
});

test("SigV4Client preserves per-request one-shot unsignableHeaders when init is reused", async () => {
  function* headersToSkip() {
    yield "x-debug-only";
  }
  const client = lambdaClient();
  const init = {
    method: "GET",
    headers: {
      "x-debug-only": "skip-me",
    },
    signing: {
      signingDate: FIXED_AMZ_DATE,
      unsignableHeaders: headersToSkip(),
    },
  };
  const first = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  const second = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  assert.equal(first.headers.get("authorization"), second.headers.get("authorization"));
  assert.doesNotMatch(first.headers.get("authorization") || "", /x-debug-only/);
  assert.doesNotMatch(second.headers.get("authorization") || "", /x-debug-only/);
});

test("signAwsRequest preserves one-shot unsignableHeaders when options are reused", async () => {
  function* headersToSkip() {
    yield "x-debug-only";
  }
  const options = {
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    signingDate: FIXED_AMZ_DATE,
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-debug-only": "skip-me",
    },
    unsignableHeaders: headersToSkip(),
  };
  const first = await signAwsRequest(options);
  const second = await signAwsRequest(options);
  assert.equal(first.headers.get("authorization"), second.headers.get("authorization"));
  assert.doesNotMatch(first.headers.get("authorization") || "", /x-debug-only/);
  assert.doesNotMatch(second.headers.get("authorization") || "", /x-debug-only/);
});

test("signAwsRequest preserves failed one-shot unsignableHeaders validation", async () => {
  function* headersToSkip() {
    yield "x-debug-only";
    yield "";
  }
  const options = {
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    signingDate: FIXED_AMZ_DATE,
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-debug-only": "skip-me",
    },
    unsignableHeaders: headersToSkip(),
  };
  const message = /unsignableHeaders must contain only non-empty strings/;
  await assert.rejects(() => signAwsRequest(options), message);
  await assert.rejects(() => signAwsRequest(options), message);
});

test("SigV4Client rereads reusable unsignableHeaders iterables", async () => {
  const unsignableHeaders = ["x-debug-only"];
  const client = lambdaClient();
  const init = {
    method: "GET",
    headers: {
      "x-debug-only": "skip-me",
      "x-extra": "skip-later",
    },
    signing: {
      signingDate: FIXED_AMZ_DATE,
      unsignableHeaders,
    },
  };
  const first = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  unsignableHeaders.push("x-extra");
  const second = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init);
  assert.match(first.headers.get("authorization") || "", /x-extra/);
  assert.doesNotMatch(first.headers.get("authorization") || "", /x-debug-only/);
  assert.doesNotMatch(second.headers.get("authorization") || "", /x-extra/);
  assert.doesNotMatch(second.headers.get("authorization") || "", /x-debug-only/);
});

test("SigV4Client.fetch snapshots per-request unsignableHeaders across retries", async () => {
  function* headersToSkip() {
    yield "x-debug-only";
  }
  const seen = [];
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      seen.push(request.headers.get("authorization") || "");
      return new Response("ok", { status: seen.length === 1 ? 500 : 200 });
    },
  });
  const response = await client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "PUT",
    headers: {
      "x-debug-only": "skip-me",
    },
    signing: {
      signingDate: FIXED_AMZ_DATE,
      unsignableHeaders: headersToSkip(),
    },
  });
  assert.equal(response.status, 200);
  assert.equal(seen.length, 2);
  assert.equal(seen[0], seen[1]);
  assert.doesNotMatch(seen[0], /x-debug-only/);
  assert.doesNotMatch(seen[1], /x-debug-only/);
});

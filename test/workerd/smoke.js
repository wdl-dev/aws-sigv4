// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { SigV4Client, signAwsRequest } from "@wdl-dev/aws-sigv4";

const ACCESS_KEY_ID = "AKIDEXAMPLE";
const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const FIXED_AMZ_DATE = "20260616T010203Z";

export default {
  async test() {
    await assertGoldenSignature();
    await assertS3RequestSignature();
    await assertDisturbedStreamRejected();
    await assertClientFetch();
    await assertSourceSignalPropagation();
    await assertFetchIgnoresSignOverride();
  },
};

async function assertS3RequestSignature() {
  const client = new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
  });
  const request = await client.sign("https://s3.us-east-1.amazonaws.com/example-bucket/objects/a%2Fb+name.txt", {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assertEqual(request instanceof Request, true, "S3 signed Request");
  assertEqual(request.url, "https://s3.us-east-1.amazonaws.com/example-bucket/objects/a%2Fb+name.txt", "S3 signed URL");
  assertEqual(request.headers.get("x-amz-content-sha256"), "UNSIGNED-PAYLOAD", "S3 payload hash");
  assertEqual(
    request.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=339773363fd76d12a21c35f2b97ea2cce1c9ccafb005e3e61c4dfea884ec7ea4",
    "S3 authorization"
  );
}

async function assertDisturbedStreamRejected() {
  for (const [service, region, method, url] of [
    ["lambda", "ap-northeast-1", "POST", "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms"],
    ["s3", "us-east-1", "PUT", "https://s3.us-east-1.amazonaws.com/example-bucket/disturbed.txt"],
  ]) {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("part1"));
        controller.enqueue(new TextEncoder().encode("part2"));
        controller.close();
      },
    });
    const reader = body.getReader();
    await reader.read();
    reader.releaseLock();
    let caught;
    try {
      await signAwsRequest({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: SECRET_ACCESS_KEY,
        service,
        region,
        method,
        url,
        body,
        signingDate: FIXED_AMZ_DATE,
      });
    } catch (error) {
      caught = error;
    }
    if (!(caught instanceof TypeError) || caught.message !== "ReadableStream body must not be disturbed or locked") {
      throw new Error(`${service} disturbed stream error: received ${String(caught)}`);
    }
    assertEqual(body.locked, false, `${service} disturbed stream lock state`);
  }
}

async function assertGoldenSignature() {
  const signed = await signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    method: "GET",
    url: "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms",
    signingDate: FIXED_AMZ_DATE,
  });
  assertEqual(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482",
    "golden authorization"
  );
}

async function assertClientFetch() {
  const attempts = [];
  const client = new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      attempts.push({
        authorization: request.headers.get("authorization"),
        body: await request.text(),
        redirect: request.redirect,
      });
      return new Response(attempts.length === 1 ? "retry" : "ok", {
        status: attempts.length === 1 ? 500 : 200,
      });
    },
  });
  const response = await client.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
    method: "PUT",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assertEqual(response.status, 200, "fetch status");
  assertEqual(await response.text(), "ok", "fetch body");
  assertEqual(attempts.length, 2, "fetch attempts");
  for (const attempt of attempts) {
    assertEqual(attempt.redirect, "manual", "request redirect mode");
    assertEqual(attempt.body, "{}", "request body");
    if (!attempt.authorization?.startsWith("AWS4-HMAC-SHA256 ")) {
      throw new Error("request authorization was not signed");
    }
  }
}

async function assertSourceSignalPropagation() {
  const controller = new AbortController();
  const reason = { code: "workerd-source-aborted" };
  let fetchCalls = 0;
  const client = new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    fetch: async (request) => {
      fetchCalls += 1;
      if (!request.headers.get("authorization")?.startsWith("AWS4-HMAC-SHA256 ")) {
        throw new Error("transport request lost authorization");
      }
      controller.abort(reason);
      assertEqual(request.signal.aborted, true, "transport signal state");
      assertEqual(request.signal.reason, reason, "transport signal reason");
      throw reason;
    },
  });
  let caught;
  try {
    await client.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
      signal: controller.signal,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
  } catch (error) {
    caught = error;
  }
  assertEqual(caught, reason, "source abort reason");
  assertEqual(fetchCalls, 1, "transport calls");
}

async function assertFetchIgnoresSignOverride() {
  let fetchCalls = 0;
  let signCalls = 0;
  const client = new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async (request) => {
      fetchCalls += 1;
      if (!request.headers.get("authorization")?.startsWith("AWS4-HMAC-SHA256 ")) {
        throw new Error("fetch request lost authorization");
      }
      return new Response(fetchCalls === 1 ? "retry" : "ok", { status: fetchCalls === 1 ? 500 : 200 });
    },
  });
  client.sign = async function unexpectedSignHook() {
    signCalls += 1;
    throw new Error("fetch must not call an overridden sign method");
  };
  const response = await client.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
    method: "PUT",
    body: "{}",
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assertEqual(response.status, 200, "sign override response");
  assertEqual(fetchCalls, 2, "sign override transport calls");
  assertEqual(signCalls, 0, "sign override calls");
}

function assertEqual(actual, expected, name) {
  if (actual !== expected) {
    throw new Error(`${name}: expected ${String(expected)}, received ${String(actual)}`);
  }
}

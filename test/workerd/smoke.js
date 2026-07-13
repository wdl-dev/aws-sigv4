// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { SigV4Client, signAwsRequest } from "@wdl-dev/aws-sigv4";

const ACCESS_KEY_ID = "AKIDEXAMPLE";
const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const FIXED_AMZ_DATE = "20260616T010203Z";

export default {
  async test() {
    await assertGoldenSignature();
    await assertClientFetch();
    await assertOverrideCannotDropSourceSignal();
    await assertNoCorsOverrideRuntimeBoundary();
  },
};

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

async function assertOverrideCannotDropSourceSignal() {
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
        throw new Error("override transport request lost authorization");
      }
      controller.abort(reason);
      assertEqual(request.signal.aborted, true, "override transport signal state");
      assertEqual(request.signal.reason, reason, "override transport signal reason");
      throw reason;
    },
  });
  const defaultSign = client.sign;
  client.sign = async function signWithoutSourceSignal(input, init) {
    const signed = await defaultSign.call(this, input, init);
    return new Request(signed, { signal: null });
  };
  let caught;
  try {
    await client.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
      signal: controller.signal,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
  } catch (error) {
    caught = error;
  }
  assertEqual(caught, reason, "override source abort reason");
  assertEqual(fetchCalls, 1, "override transport calls");
}

async function assertNoCorsOverrideRuntimeBoundary() {
  let fetchCalls = 0;
  const client = new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    fetch: async (request) => {
      fetchCalls += 1;
      assertEqual(request.mode, undefined, "workerd no-cors mode");
      if (!request.headers.get("authorization")?.startsWith("AWS4-HMAC-SHA256 ")) {
        throw new Error("no-cors override request lost authorization");
      }
      return new Response("ok");
    },
  });
  const defaultSign = client.sign;
  client.sign = async function signWithIgnoredNoCorsMode(input, init) {
    const signed = await defaultSign.call(this, input, init);
    return new Request(signed, { mode: "no-cors" });
  };
  const response = await client.fetch("https://lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms", {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assertEqual(response.status, 200, "no-cors override response");
  assertEqual(fetchCalls, 1, "no-cors override transport calls");
}

function assertEqual(actual, expected, name) {
  if (actual !== expected) {
    throw new Error(`${name}: expected ${String(expected)}, received ${String(actual)}`);
  }
}

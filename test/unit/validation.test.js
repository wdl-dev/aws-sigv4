// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { SigV4Client, signAwsRequest } from "../../dist/index.js";

import {
  ACCESS_KEY_ID,
  EXECUTE_API_ENDPOINT,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  SECRET_ACCESS_KEY,
  assertHelloStreamReadable,
  executeApiClient,
  helloStream,
  lambdaClient,
  lambdaRequest,
  s3Client,
  s3Request,
} from "./helpers.js";
test("signing rejects non-HTTP URLs", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: "ftp://example.com/path",
      }),
    /url must use http: or https:/
  );
});

test("signers reject missing or non-object option bags", async () => {
  for (const options of [undefined, null, "invalid"]) {
    assert.throws(() => new SigV4Client(options), /SigV4Client options are required/);
    await assert.rejects(() => signAwsRequest(options), /signAwsRequest options are required/);
  }
});

test("signAwsRequest rejects a missing URL", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: SECRET_ACCESS_KEY,
        service: "lambda",
        region: "ap-northeast-1",
      }),
    /url is a required option/
  );
});

test("signing rejects string URLs with unescaped whitespace", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: "https://lambda.ap-northeast-1.amazonaws.com/a b?x=y z",
      }),
    /url must not contain unescaped whitespace/
  );
});

test("signing rejects raw C0 and DEL control characters in string URLs", async () => {
  const controls = [...Array.from({ length: 0x20 }, (_value, codePoint) => codePoint), 0x7f];
  for (const codePoint of controls) {
    const control = String.fromCodePoint(codePoint);
    for (const url of [
      `${control}${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      `${LAMBDA_ENDPOINT}/2025-09-09/a${control}b`,
      `${LAMBDA_ENDPOINT}/2025-09-09/microvms${control}`,
      `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=a${control}b`,
      `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=value${control}`,
    ]) {
      await assert.rejects(
        () => lambdaRequest({ method: "GET", url }),
        /url must not contain unescaped whitespace or control characters/
      );
    }
  }
});

test("signing rejects string URLs without scheme slashes", async () => {
  await assert.rejects(
    () =>
      s3Request({
        method: "GET",
        url: "https:example-bucket.s3.amazonaws.com/key.txt?x=1",
      }),
    /url must include scheme:\/\/host/
  );
});

test("signing rejects string URLs with empty authority", async () => {
  await assert.rejects(
    () =>
      s3Request({
        method: "GET",
        url: "https:///example-bucket/key.txt",
      }),
    /url must include scheme:\/\/host/
  );
});

test("signing rejects string URLs with backslashes", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: String.raw`${LAMBDA_ENDPOINT}/2025-09-09/a\b.txt`,
      }),
    /url must not contain backslashes/
  );
  await assert.rejects(
    () =>
      s3Client().sign(String.raw`${S3_ENDPOINT}/example-bucket/a\b.txt`, {
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /url must not contain backslashes/
  );
});

test("signing rejects string URLs with userinfo", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: "https://user:pass@lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms",
      }),
    /url must not include username or password/
  );
});

test("signing rejects malformed percent escapes in string URLs", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/%ZZ?token=%`,
      }),
    /url must not contain malformed percent encoding/
  );
});

test("signing rejects malformed percent escapes in URL objects", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: new URL(`${LAMBDA_ENDPOINT}/2025-09-09/%ZZ?token=%`),
      }),
    /url must not contain malformed percent encoding/
  );
});

test("signing rejects invalid UTF-16 in string URLs", async () => {
  for (const url of [`${LAMBDA_ENDPOINT}/2025-09-09/\uD800`, `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=\uD800`]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          method: "GET",
          url,
        }),
      /url must not contain invalid UTF-16/
    );
  }
});

test("signing ignores invalid UTF-16 in string URL fragments", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms#\uD800`,
  });
  assert.equal(signed.url, `${LAMBDA_ENDPOINT}/2025-09-09/microvms`);
});

test("SigV4Client rejects dot-segment string URLs", async () => {
  const client = s3Client();
  for (const segment of ["..", "%2e%2e", ".%2e", "%2e.", ".%2E", "%2E."]) {
    await assert.rejects(
      () =>
        client.sign(`${S3_ENDPOINT}/example-bucket/a/${segment}/b.txt`, {
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      /cannot represent s3 URLs with dot segments/
    );
  }
  await assert.rejects(
    () =>
      client.sign("https://lambda.us-east-1.amazonaws.com/a/../b", {
        signing: { service: "lambda", region: "us-east-1", signingDate: FIXED_AMZ_DATE },
      }),
    /cannot represent lambda URLs with dot segments/
  );
});

test("SigV4Client rejects dot-segment URLs before reading stream bodies", async () => {
  const body = helloStream();
  const client = lambdaClient();
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/a/../microvms`, {
        method: "POST",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /cannot represent lambda URLs with dot segments/
  );
  await assertHelloStreamReadable(body);
});

test("SigV4Client.fetch rejects dot-segment URLs before reading stream bodies", async () => {
  const body = helloStream();
  const client = lambdaClient({
    fetch: async () => new Response("should not fetch"),
  });
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/a/../microvms`, {
        method: "PUT",
        body,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /cannot represent lambda URLs with dot segments/
  );
  await assertHelloStreamReadable(body);
});

test("signing rejects credential components with slash separators", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: "AKID/EXAMPLE",
        secretAccessKey: SECRET_ACCESS_KEY,
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /accessKeyId must not contain \//
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        service: "bad/service",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /service must not contain \//
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        region: "bad/region",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /region must not contain \//
  );
});

test("signing rejects credential fields with control characters", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: "AKID\nEXAMPLE",
        secretAccessKey: SECRET_ACCESS_KEY,
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /accessKeyId must not contain control characters/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        sessionToken: "token\r\nvalue",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /sessionToken must not contain control characters/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        service: "lambda\n",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /service must not contain control characters/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        region: "ap-northeast-1\u007f",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /region must not contain control characters/
  );
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: "SECRET\nKEY",
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /secretAccessKey must not contain control characters/
  );
  assert.throws(
    () => lambdaClient({ secretAccessKey: "SECRET\rKEY" }),
    /secretAccessKey must not contain control characters/
  );
});

test("signing rejects malformed UTF-16 secret access keys", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: "SECRET\ud800KEY",
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /secretAccessKey must contain well-formed UTF-16/
  );
  assert.throws(
    () => lambdaClient({ secretAccessKey: "SECRET\ud801KEY" }),
    /secretAccessKey must contain well-formed UTF-16/
  );
});

test("signing rejects uppercase service and region values", async () => {
  for (const [name, value] of [
    ["service", "S3"],
    ["region", "US-EAST-1"],
  ]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          [name]: value,
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        }),
      new RegExp(`${name} must be lowercase`)
    );
    assert.throws(() => lambdaClient({ [name]: value }), new RegExp(`${name} must be lowercase`));
    await assert.rejects(
      () =>
        lambdaClient().sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          signing: { [name]: value },
        }),
      new RegExp(`init\\.signing\\.${name} must be lowercase`)
    );
  }
});

test("signing rejects credential components with whitespace", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: "AKID EXAMPLE",
        secretAccessKey: SECRET_ACCESS_KEY,
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /accessKeyId must not contain whitespace/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        service: "lambda test",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /service must not contain whitespace/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        region: "ap northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /region must not contain whitespace/
  );
});

test("signing rejects non-printable credential components", async () => {
  await assert.rejects(
    () =>
      signAwsRequest({
        accessKeyId: "AKIDÉXAMPLE",
        secretAccessKey: SECRET_ACCESS_KEY,
        service: "lambda",
        region: "ap-northeast-1",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: FIXED_AMZ_DATE,
      }),
    /accessKeyId must contain only printable ASCII characters/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        service: "lambdé",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /service must contain only printable ASCII characters/
  );
  assert.throws(
    () => lambdaClient({ region: "ap-northeast-é" }),
    /region must contain only printable ASCII characters/
  );
});

test("signing rejects session tokens with surrounding whitespace", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        sessionToken: " token",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /sessionToken must not contain leading or trailing whitespace/
  );
  assert.throws(
    () => lambdaClient({ sessionToken: "token " }),
    /sessionToken must not contain leading or trailing whitespace/
  );
});

test("signing rejects non-printable session tokens", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        sessionToken: "tokén",
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /sessionToken must contain only printable ASCII characters/
  );
  assert.throws(
    () => lambdaClient({ sessionToken: "tokén" }),
    /sessionToken must contain only printable ASCII characters/
  );
});

test("signing rejects Authorization parameter separators in credential components", async () => {
  for (const [name, value] of [
    ["accessKeyId", "AKID,Injected=x"],
    ["service", "s3,Injected=x"],
    ["region", "us-east-1=Injected"],
    ["service", "lambda;Injected"],
  ]) {
    await assert.rejects(
      () =>
        signAwsRequest({
          accessKeyId: name === "accessKeyId" ? value : ACCESS_KEY_ID,
          secretAccessKey: SECRET_ACCESS_KEY,
          service: name === "service" ? value : "lambda",
          region: name === "region" ? value : "ap-northeast-1",
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
          signingDate: FIXED_AMZ_DATE,
        }),
      new RegExp(`${name} must not contain Authorization parameter separators`)
    );
  }
});

test("signing rejects non-string session tokens", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        sessionToken: 123,
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
    /sessionToken must be a non-empty string/
  );
  assert.throws(
    () =>
      new SigV4Client({
        accessKeyId: ACCESS_KEY_ID,
        secretAccessKey: SECRET_ACCESS_KEY,
        sessionToken: 123,
        service: "lambda",
        region: "ap-northeast-1",
      }),
    /sessionToken must be a non-empty string/
  );
});

test("SigV4Client rejects credential and cache overrides in init.signing", async () => {
  const client = lambdaClient();
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          signingDate: FIXED_AMZ_DATE,
          secretAccessKey: "SECRET2",
        },
      }),
    /init\.signing\.secretAccessKey cannot override/
  );
  await assert.rejects(
    () =>
      client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          cache: new Map(),
        },
      }),
    /init\.signing\.cache cannot override/
  );
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          ["secretAccessKey\n\u001b[31m"]: "SECRET2",
        },
      }),
    (err) => {
      assert.equal(err instanceof TypeError, true);
      assert.match(err.message, /init\.signing option cannot override/);
      assert.equal(err.message.includes("\n"), false);
      assert.equal(err.message.includes("\u001b"), false);
      return true;
    }
  );
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          "": true,
        },
      }),
    /init\.signing option cannot override/
  );
});

test("SigV4Client rejects non-object init.signing values", async () => {
  const client = lambdaClient();
  for (const signing of ["bad", true, 123, null]) {
    await assert.rejects(
      () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, { signing }),
      /init\.signing must be an object/
    );
  }
});

test("SigV4Client treats null service region and signingDate as defaults", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-06-16T01:02:03Z") });
  const signed = await lambdaClient().sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    signing: {
      service: null,
      region: null,
      signingDate: null,
    },
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
  assert.match(
    signed.headers.get("authorization") || "",
    /Credential=AKIDEXAMPLE\/20260616\/ap-northeast-1\/lambda\/aws4_request/
  );
});

test("SigV4Client ignores inherited signing options", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-06-16T01:02:03Z") });
  const signing = Object.create({
    service: "lambda",
    region: "us-east-1",
    signingDate: "20270101T000000Z",
    unsignedPayload: true,
    signAllHeaders: true,
    unsignableHeaders: ["x-extra"],
    doubleUrlEncode: true,
  });
  const url = `${EXECUTE_API_ENDPOINT}/prod/my+folder/a%2Fb/%7E`;
  const init = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-extra": "keep-me",
    },
    body: "{}",
  };
  const expected = await executeApiClient().sign(url, {
    ...init,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  const signed = await executeApiClient().sign(url, {
    ...init,
    signing,
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
  assert.equal(signed.headers.get("x-amz-content-sha256"), expected.headers.get("x-amz-content-sha256"));
  assert.equal(signed.headers.get("authorization"), expected.headers.get("authorization"));
});

test("signing rejects non-boolean signing options", async () => {
  assert.throws(() => lambdaClient({ unsignedPayload: "false" }), /unsignedPayload must be a boolean/);
  assert.throws(() => lambdaClient({ doubleUrlEncode: "false" }), /doubleUrlEncode must be a boolean/);
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "POST",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        body: "{}",
        unsignedPayload: "false",
      }),
    /unsignedPayload must be a boolean/
  );
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        doubleUrlEncode: "false",
      }),
    /doubleUrlEncode must be a boolean/
  );
  const client = lambdaClient();
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          signAllHeaders: "false",
        },
      }),
    /init\.signing\.signAllHeaders must be a boolean/
  );
  await assert.rejects(
    () =>
      client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        signing: {
          doubleUrlEncode: "false",
        },
      }),
    /init\.signing\.doubleUrlEncode must be a boolean/
  );
});

// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-FileCopyrightText: 2019 Amazon.com, Inc. or its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";

import { signAwsRequest } from "../../dist/index.js";

import {
  ACCESS_KEY_ID,
  AWS_S3_EXAMPLE_AMZ_DATE,
  AWS_S3_HEADER_AUTH_FIXTURES,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_FIXTURES,
  SECRET_ACCESS_KEY,
  SESSION_TOKEN,
  awsS3ExampleRequest,
  lambdaRequest,
  s3Client,
} from "./helpers.js";

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function hmacBytes(key, value) {
  return createHmac("sha256", key).update(value).digest();
}

function hmacHex(key, value) {
  return createHmac("sha256", key).update(value).digest("hex");
}

function signingKey(date, region, service) {
  return hmacBytes(hmacBytes(hmacBytes(hmacBytes(`AWS4${SECRET_ACCESS_KEY}`, date), region), service), "aws4_request");
}

const AWS_SIGV4_TESTSUITE_SESSION_TOKEN =
  "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";

const AWS_SIGV4_TESTSUITE_FIXTURES = [
  {
    name: "get-vanilla",
    method: "GET",
    url: "https://example.amazonaws.com/",
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  },
  {
    name: "get-unreserved",
    method: "GET",
    url: "https://example.amazonaws.com/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=07ef7494c76fa4850883e2b006601f940f8a34d404d0cfa977f52a65bbf5f24f",
  },
  {
    name: "normalize-path/get-special-character",
    method: "GET",
    url: "https://example.amazonaws.com/example/$delete",
    doubleUrlEncode: true,
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=a853c9b21b528b19643d00910d35b83a10c366a10833ceefb45edd6c80e40f27",
  },
  {
    name: "get-vanilla-query-order-key-case",
    method: "GET",
    url: "https://example.amazonaws.com/?Param2=value2&Param1=value1",
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
  },
  {
    name: "get-header-value-trim",
    method: "GET",
    url: "https://example.amazonaws.com/",
    headers: {
      "My-Header1": " value1",
      "My-Header2": '"a   b   c"',
    },
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;my-header1;my-header2;x-amz-date, Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
  },
  {
    name: "post-sts-header-before",
    method: "POST",
    url: "https://example.amazonaws.com/",
    sessionToken: AWS_SIGV4_TESTSUITE_SESSION_TOKEN,
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead",
  },
];

test("AWS SigV4 testsuite vectors match the published signatures", async () => {
  for (const fixture of AWS_SIGV4_TESTSUITE_FIXTURES) {
    const signed = await signAwsRequest({
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET_ACCESS_KEY,
      sessionToken: fixture.sessionToken,
      service: "service",
      region: "us-east-1",
      method: fixture.method,
      url: fixture.url,
      headers: fixture.headers,
      doubleUrlEncode: fixture.doubleUrlEncode,
      signingDate: "20150830T123600Z",
    });
    assert.equal(signed.headers.get("authorization"), fixture.expectedAuthorization, fixture.name);
    assert.equal(signed.headers.get("x-amz-date"), "20150830T123600Z", fixture.name);
    assert.equal(signed.headers.get("x-amz-security-token"), fixture.sessionToken ?? null, fixture.name);
  }
});

test("S3 unsigned payload golden vectors match expected signatures", async () => {
  for (const fixture of S3_FIXTURES) {
    const client = s3Client({
      sessionToken: fixture.sessionToken,
      cache: new Map(),
    });
    const signed = await client.sign(fixture.url, {
      ...fixture.init,
      signing: { signingDate: FIXED_AMZ_DATE },
    });
    assert.equal(signed.url, fixture.expectedUrl, fixture.name);
    assert.equal(signed.headers.get("authorization"), fixture.expectedAuthorization, fixture.name);
    assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE, fixture.name);
    assert.equal(signed.headers.get("x-amz-content-sha256"), fixture.expectedContentSha256, fixture.name);
    assert.equal(signed.headers.get("x-amz-security-token"), fixture.expectedSecurityToken ?? null, fixture.name);
  }
});

test("AWS S3 official header auth examples match the published signatures", async () => {
  for (const fixture of AWS_S3_HEADER_AUTH_FIXTURES) {
    const signed = await awsS3ExampleRequest({
      method: fixture.method,
      url: fixture.url,
      headers: fixture.headers,
      body: fixture.body,
    });
    assert.equal(signed.url, fixture.url, fixture.name);
    assert.equal(signed.headers.get("authorization"), fixture.expectedAuthorization, fixture.name);
    assert.equal(signed.headers.get("x-amz-date"), AWS_S3_EXAMPLE_AMZ_DATE, fixture.name);
    assert.equal(signed.headers.get("x-amz-content-sha256"), fixture.expectedContentSha256, fixture.name);
  }
});

test("Lambda REST-JSON requests sign with service=lambda and a real payload hash", async () => {
  const body = JSON.stringify({
    imageIdentifier: "arn:aws:lambda:ap-northeast-1:123456789012:microvm-image/demo:1",
    clientToken: "session-001",
  });
  const signed = await lambdaRequest({
    sessionToken: SESSION_TOKEN,
    method: "POST",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "content-type": "application/json",
    },
    body,
  });
  assert.equal(
    signed.headers.get("x-amz-content-sha256"),
    "8bb2ab7755170b90b5a5cd18d9a53a337915f054dfa865d1142be5cdc61dd825"
  );
  assert.equal(signed.headers.get("x-amz-target"), null);
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=1021b668fd3583c38a9372920957ee861556956b7599ff5995bbfba08082b37a"
  );
});

test("AWS IAM ListUsers official SigV4 example matches the published signature", async () => {
  const signed = await signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "iam",
    region: "us-east-1",
    method: "GET",
    url: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
    headers: {
      "content-type": "application/x-www-form-urlencoded; charset=utf-8",
    },
    signingDate: "20150830T123600Z",
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
  );
});

test("temporary credentials sign x-amz-security-token in canonical headers", async () => {
  const signed = await signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    sessionToken: SESSION_TOKEN,
    service: "sts",
    region: "us-east-1",
    method: "GET",
    url: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
    signingDate: FIXED_AMZ_DATE,
  });
  const canonicalRequest = [
    "GET",
    "/",
    "Action=GetCallerIdentity&Version=2011-06-15",
    "host:sts.amazonaws.com\nx-amz-date:20260616T010203Z\nx-amz-security-token:session-token-example\n",
    "host;x-amz-date;x-amz-security-token",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    FIXED_AMZ_DATE,
    "20260616/us-east-1/sts/aws4_request",
    sha256Hex(canonicalRequest),
  ].join("\n");
  const signature = hmacHex(signingKey("20260616", "us-east-1", "sts"), stringToSign);
  assert.equal(signed.headers.get("x-amz-security-token"), SESSION_TOKEN);
  assert.equal(
    signed.headers.get("authorization"),
    `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=${signature}`
  );
});

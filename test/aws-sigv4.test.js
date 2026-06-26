// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { SigV4Client, signAwsRequest } from "../dist/index.js";

const ACCESS_KEY_ID = "AKIDEXAMPLE";
const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const SESSION_TOKEN = "session-token-example";
const FIXED_AMZ_DATE = "20260616T010203Z";
const LAMBDA_ENDPOINT = "https://lambda.ap-northeast-1.amazonaws.com";
const S3_ENDPOINT = "https://s3.us-east-1.amazonaws.com";

function lambdaClient(options = {}) {
  return new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    ...options,
  });
}

function s3Client(options = {}) {
  return new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
    ...options,
  });
}

function lambdaRequest(options) {
  return signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    signingDate: FIXED_AMZ_DATE,
    ...options,
  });
}

function s3Request(options) {
  return signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
    signingDate: FIXED_AMZ_DATE,
    ...options,
  });
}

const S3_FIXTURES = [
  {
    name: "put object signs S3 path, query, metadata, and unsigned payload",
    url: `${S3_ENDPOINT}/example-bucket/objects/a%26b.txt?partNumber=1&uploadId=upload-id`,
    init: {
      method: "PUT",
      headers: {
        "content-type": "text/plain",
        "x-amz-meta-color": "blue",
      },
      body: "hello",
    },
    expectedAuthorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-color, Signature=e815879fb7e43ffa6defedacb4cbaa791e3d7d44edbff342ddc5b6b8cfbdaece",
    expectedContentSha256: "UNSIGNED-PAYLOAD",
    expectedUrl: `${S3_ENDPOINT}/example-bucket/objects/a%26b.txt?partNumber=1&uploadId=upload-id`,
  },
  {
    name: "delete objects signs explicit payload hash and checksum header",
    url: `${S3_ENDPOINT}/example-bucket?delete`,
    init: {
      method: "POST",
      headers: {
        "content-type": "application/xml",
        "x-amz-checksum-sha256": "checksum-base64",
        "x-amz-content-sha256": "e2000f6b1fc1db795626ddaf9c13324157e9f56cb7820b40d7c3253a08ee5b91",
      },
      body: "<Delete/>",
    },
    expectedAuthorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date, Signature=b4352c2e0906d0a76dcc8b28c839b72629870b321e80dda6fff9b4c066d52910",
    expectedContentSha256: "e2000f6b1fc1db795626ddaf9c13324157e9f56cb7820b40d7c3253a08ee5b91",
    expectedUrl: `${S3_ENDPOINT}/example-bucket?delete`,
  },
  {
    name: "session token participates in signed headers",
    url: `${S3_ENDPOINT}/example-bucket/objects/session.txt`,
    sessionToken: SESSION_TOKEN,
    init: {
      method: "HEAD",
    },
    expectedAuthorization: "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=0cc131c1da50954868d149555460960971cfae3822c6b2cf6984925a04ff5d10",
    expectedContentSha256: "UNSIGNED-PAYLOAD",
    expectedSecurityToken: SESSION_TOKEN,
    expectedUrl: `${S3_ENDPOINT}/example-bucket/objects/session.txt`,
  },
];

test("S3 signing supports unsigned payload golden vectors", async () => {
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

test("Lambda MicroVMs REST-JSON requests sign with service=lambda and real payload hash", async () => {
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

test("canonical query sorting uses codepoint order, not locale collation", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1&B=2`,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=fefeea161f138004a24f462230b354d304be171118f0c2a0e4ade13cf8169369"
  );
});

test("canonical query sorting preserves duplicate non-S3 keys by encoded key then value", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?z=last&a=2&a=1`,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=ea7951b35d4ab50e9bf254a468dccc34cb903143775668a66df4085a573c5973"
  );
});

test("canonical query preserves literal plus signs", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=a+b&space=a%20b`,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=d551b1bd723ebcdc7b57683d39a6d4c8950162cd34fe12483b7a81d677f11662"
  );
});

test("canonical query preserves invalid UTF-8 percent bytes", async () => {
  const signedInvalidUtf8 = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=%C0`,
  });
  const signedEscapedPercent = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=%25C0`,
  });
  assert.notEqual(
    signedInvalidUtf8.headers.get("authorization"),
    signedEscapedPercent.headers.get("authorization")
  );
});

test("canonical query preserves empty keys", async () => {
  const base = {
    method: "GET",
  };
  const signedEmptyKey = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?=v&a=1`,
  });
  const signedWithoutEmptyKey = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1`,
  });
  assert.notEqual(
    signedEmptyKey.headers.get("authorization"),
    signedWithoutEmptyKey.headers.get("authorization")
  );
});

test("canonical query ignores empty segments", async () => {
  const base = {
    method: "GET",
  };
  const signedEmptyMiddle = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1&&b=2`,
  });
  const signedNoEmptyMiddle = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1&b=2`,
  });
  const signedLeadingEmpty = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?&a=1`,
  });
  const signedTrailingEmpty = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1&`,
  });
  const signedNoEmpty = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?a=1`,
  });
  assert.equal(
    signedEmptyMiddle.headers.get("authorization"),
    signedNoEmptyMiddle.headers.get("authorization")
  );
  assert.equal(
    signedLeadingEmpty.headers.get("authorization"),
    signedNoEmpty.headers.get("authorization")
  );
  assert.equal(
    signedTrailingEmpty.headers.get("authorization"),
    signedNoEmpty.headers.get("authorization")
  );
  assert.equal(
    signedLeadingEmpty.headers.get("authorization"),
    signedTrailingEmpty.headers.get("authorization")
  );
});

test("canonical query preserves duplicate S3 keys", async () => {
  const signed = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket?partNumber=10&partNumber=2&uploadId=upload-id`,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=aad4b939f1fe3d6ce15db1f61e32b1675068d61349dfda872e91cc4fe70c8465"
  );
});

test("canonical S3 paths preserve literal plus signs", async () => {
  const base = {
    method: "GET",
  };
  const signedLiteralPlus = await s3Request({
    ...base,
    url: `${S3_ENDPOINT}/example-bucket/my+folder/file.txt`,
  });
  const signedEncodedPlus = await s3Request({
    ...base,
    url: `${S3_ENDPOINT}/example-bucket/my%2Bfolder/file.txt`,
  });
  assert.equal(
    signedLiteralPlus.headers.get("authorization"),
    signedEncodedPlus.headers.get("authorization")
  );
});

test("canonical S3 paths preserve encoded slash bytes", async () => {
  const base = {
    method: "GET",
  };
  const signedPathSlash = await s3Request({
    ...base,
    url: `${S3_ENDPOINT}/example-bucket/a/b.txt`,
  });
  const signedEncodedSlash = await s3Request({
    ...base,
    url: `${S3_ENDPOINT}/example-bucket/a%2Fb.txt`,
  });
  assert.notEqual(
    signedEncodedSlash.headers.get("authorization"),
    signedPathSlash.headers.get("authorization")
  );
});

test("canonical S3 paths preserve dot segments from string URLs", async () => {
  const base = {
    method: "GET",
  };
  const literalDotSegmentUrl = `${S3_ENDPOINT}/example-bucket/a/../b.txt`;
  const encodedDotSegmentUrl = `${S3_ENDPOINT}/example-bucket/a/%2E%2E/b.txt`;
  const normalizedUrl = `${S3_ENDPOINT}/example-bucket/b.txt`;
  const signedLiteralDotSegment = await s3Request({
    ...base,
    url: literalDotSegmentUrl,
  });
  const signedEncodedDotSegment = await s3Request({
    ...base,
    url: encodedDotSegmentUrl,
  });
  const signedNormalized = await s3Request({
    ...base,
    url: normalizedUrl,
  });
  assert.equal(signedLiteralDotSegment.url, literalDotSegmentUrl);
  assert.equal(signedEncodedDotSegment.url, encodedDotSegmentUrl);
  assert.notEqual(
    signedLiteralDotSegment.headers.get("authorization"),
    signedNormalized.headers.get("authorization")
  );
  assert.notEqual(
    signedEncodedDotSegment.headers.get("authorization"),
    signedNormalized.headers.get("authorization")
  );
});

test("string URL output normalizes origin while preserving raw path and query", async () => {
  const signedDefaultPort = await lambdaRequest({
    method: "GET",
    url: "https://lambda.ap-northeast-1.amazonaws.com:443/2025-09-09//microvms?=v",
  });
  const signedWithoutDefaultPort = await lambdaRequest({
    method: "GET",
    url: "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms?=v",
  });
  assert.equal(
    signedDefaultPort.url,
    "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms?=v"
  );
  assert.equal(
    signedDefaultPort.headers.get("authorization"),
    signedWithoutDefaultPort.headers.get("authorization")
  );
});

test("URL object inputs use platform-normalized path and query", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: new URL(`${LAMBDA_ENDPOINT}/2025-09-09/a%2Fb?token=ab+cd&B=2`),
  });
  assert.equal(signed.url, `${LAMBDA_ENDPOINT}/2025-09-09/a%2Fb?token=ab+cd&B=2`);
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=6994c4a7114a23fe9ffc83188c968d741d73fb88a6f3e00d889e81085006c930"
  );
});

test("canonical paths preserve repeated slashes for non-S3 services", async () => {
  const base = {
    method: "GET",
  };
  const signedRepeatedSlash = await lambdaRequest({
    ...base,
    url: "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms",
  });
  const signedSingleSlash = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
  });
  assert.equal(
    signedRepeatedSlash.url,
    "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms"
  );
  assert.notEqual(
    signedRepeatedSlash.headers.get("authorization"),
    signedSingleSlash.headers.get("authorization")
  );
});

test("S3 signing includes content-type by default", async () => {
  const signed = await s3Request({
    method: "PUT",
    url: `${S3_ENDPOINT}/example-bucket/content-type.txt`,
    headers: {
      "content-type": "text/plain",
    },
    body: "hello",
  });
  assert.match(
    signed.headers.get("authorization") || "",
    /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/
  );
});

test("canonical headers trim and collapse whitespace", async () => {
  const trimmed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "a b",
    },
  });
  const spaced = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "  a   b  ",
    },
  });
  assert.equal(spaced.headers.get("authorization"), trimmed.headers.get("authorization"));
});

test("canonical headers preserve non-OWS whitespace", async () => {
  const signedNbsp = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "a\u00a0b",
    },
  });
  const signedSpace = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "x-amz-meta-space": "a b",
    },
  });
  assert.notEqual(signedNbsp.headers.get("authorization"), signedSpace.headers.get("authorization"));
});

test("range is signed by default when present", async () => {
  const signed = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/ranged.txt`,
    headers: {
      range: "bytes=0-99",
    },
  });
  assert.match(
    signed.headers.get("authorization") || "",
    /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date/
  );
});

test("signing returns a host header for custom transports", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
  });
  assert.equal(signed.headers.get("host"), "lambda.ap-northeast-1.amazonaws.com");
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=host;x-amz-date/);
});

test("explicit host headers are normalized without duplicate signed headers", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      host: "evil.example.com",
    },
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.equal(signed.headers.get("host"), "lambda.ap-northeast-1.amazonaws.com");
  assert.match(authorization, /SignedHeaders=host;x-amz-date/);
  assert.doesNotMatch(authorization, /SignedHeaders=host;host/);
});

test("explicit x-amz-content-sha256 controls the canonical payload hash", async () => {
  const signed = await lambdaRequest({
    method: "POST",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    headers: {
      "content-type": "application/json",
      "x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    body: "ignored",
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=20c8af3e452c87173cbbc0cdf9dcdd703dfcf7b03a11ec2c86ae8139f886cbc4"
  );
});

test("generated content-type headers are signed before Request construction", async () => {
  const client = lambdaClient();
  const params = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    body: new URLSearchParams({ hello: "world" }),
    signing: { signingDate: FIXED_AMZ_DATE, signAllHeaders: true },
  });
  assert.equal(params.headers.get("content-type"), "application/x-www-form-urlencoded;charset=UTF-8");
  assert.match(params.headers.get("authorization") || "", /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);

  const blob = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    body: new Blob(["hello"], { type: "text/plain" }),
    signing: { signingDate: FIXED_AMZ_DATE, signAllHeaders: true },
  });
  assert.equal(blob.headers.get("content-type"), "text/plain");
  assert.match(blob.headers.get("authorization") || "", /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);
});

test("S3 unsigned FormData signs the generated boundary", async () => {
  const client = s3Client();
  const form = new FormData();
  form.set("message", "hello");
  const signed = await client.sign(`${S3_ENDPOINT}/example-bucket/form-data.txt`, {
    method: "PUT",
    body: form,
    signing: { signingDate: FIXED_AMZ_DATE, signAllHeaders: true },
  });
  const contentType = signed.headers.get("content-type") || "";
  const boundary = /boundary=(.+)$/u.exec(contentType)?.[1];
  assert.match(contentType, /^multipart\/form-data; boundary=/);
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);
  assert.ok(boundary);
  assert.match(await signed.clone().text(), new RegExp(boundary));
});

test("payload hashing reuses Uint8Array bodies without copying", async () => {
  const body = new Uint8Array([123, 34, 111, 107, 34, 58, 116, 114, 117, 101, 125]);
  const digestInputs = [];
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  crypto.subtle.digest = async (algorithm, data) => {
    digestInputs.push(data);
    return originalDigest(algorithm, data);
  };
  try {
    await lambdaRequest({
      method: "POST",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      headers: {
        "content-type": "application/json",
      },
      body,
    });
  } finally {
    crypto.subtle.digest = originalDigest;
  }
  assert.equal(digestInputs.includes(body), true);
});

test("signing rejects empty x-amz-content-sha256", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "POST",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      headers: {
        "content-type": "application/json",
        "x-amz-content-sha256": "",
      },
      body: "{}",
    }),
    /x-amz-content-sha256 must not be empty/
  );
});

test("signed S3 payloads send x-amz-content-sha256", async () => {
  const signed = await s3Request({
    method: "PUT",
    url: `${S3_ENDPOINT}/example-bucket/signed-payload.txt`,
    body: "hello",
    unsignedPayload: false,
  });
  assert.equal(
    signed.headers.get("x-amz-content-sha256"),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
  );
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);
});

test("signingDate accepts Date objects", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: new Date("2026-06-16T01:02:03.000Z"),
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=2d7bf3729352388cc6717c97bbd11201eb3cd082231c420ac07bfa318cfb2482"
  );
});

test("signingDate ignores Date subclass toISOString overrides", async () => {
  class BadDate extends Date {
    toISOString() {
      return "BAD";
    }
  }
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: new BadDate("2026-06-16T01:02:03.000Z"),
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
});

test("signingDate rejects Date subclasses with invalid primitive time", async () => {
  class BadDate extends Date {
    getTime() {
      return 0;
    }
  }
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: new BadDate("not-a-date"),
    }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects Date prototype objects with a stable message", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: Object.create(Date.prototype),
    }),
    /signingDate must be a valid Date/
  );
});

test("signingDate accepts ISO-8601 strings", async () => {
  const dateSigned = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: new Date("2026-06-16T01:02:03.000Z"),
  });
  const stringSigned = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: "2026-06-16T01:02:03Z",
  });
  assert.equal(stringSigned.headers.get("x-amz-date"), FIXED_AMZ_DATE);
  assert.equal(stringSigned.headers.get("authorization"), dateSigned.headers.get("authorization"));

  const basicOffsetSigned = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: "2026-06-15T20:02:03-0500",
  });
  assert.equal(basicOffsetSigned.headers.get("x-amz-date"), FIXED_AMZ_DATE);
  assert.equal(basicOffsetSigned.headers.get("authorization"), dateSigned.headers.get("authorization"));
});

test("signingDate rejects ISO-8601 strings without timezone", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: "2026-06-16T01:02:03",
    }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects non-ISO strings with timezone suffixes", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: "06/16/2026 01:02:03 +00:00",
    }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects invalid compact AWS date strings", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: "20269999T999999Z",
    }),
    /signingDate must be a valid Date/
  );
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: "20260229T010203Z",
    }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects invalid ISO calendar dates", async () => {
  for (const signingDate of [
    "2026-02-30T00:00:00Z",
    "2026-04-31T00:00:00Z",
    "2027-02-29T00:00:00Z",
  ]) {
    await assert.rejects(
      () => lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate,
      }),
      /signingDate must be a valid Date/
    );
  }
});

test("signingDate rejects non-Date objects with a stable message", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate: {},
    }),
    /signingDate must be a valid Date/
  );
});

test("signing rejects non-HTTP URLs", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: "ftp://example.com/path",
    }),
    /url must use http: or https:/
  );
});

test("signing rejects string URLs with unescaped whitespace", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: "https://lambda.ap-northeast-1.amazonaws.com/a b?x=y z",
    }),
    /url must not contain unescaped whitespace/
  );
});

test("signing rejects string URLs without scheme slashes", async () => {
  await assert.rejects(
    () => s3Request({
      method: "GET",
      url: "https:example-bucket.s3.amazonaws.com/key.txt?x=1",
    }),
    /url must include scheme:\/\/host/
  );
});

test("signing rejects string URLs with backslashes", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: String.raw`${LAMBDA_ENDPOINT}/2025-09-09/a\b.txt`,
    }),
    /url must not contain backslashes/
  );
  await assert.rejects(
    () => s3Client().sign(String.raw`${S3_ENDPOINT}/example-bucket/a\b.txt`, {
      signing: { signingDate: FIXED_AMZ_DATE },
    }),
    /url must not contain backslashes/
  );
});

test("signing rejects string URLs with userinfo", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: "https://user:pass@lambda.ap-northeast-1.amazonaws.com/2025-09-09/microvms",
    }),
    /url must not include username or password/
  );
});

test("signing rejects malformed percent escapes in string URLs", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/%ZZ?token=%`,
    }),
    /url must not contain malformed percent encoding/
  );
});

test("signing rejects malformed percent escapes in URL objects", async () => {
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: new URL(`${LAMBDA_ENDPOINT}/2025-09-09/%ZZ?token=%`),
    }),
    /url must not contain malformed percent encoding/
  );
});

test("signing rejects invalid UTF-16 in string URLs", async () => {
  for (const url of [
    `${LAMBDA_ENDPOINT}/2025-09-09/\uD800`,
    `${LAMBDA_ENDPOINT}/2025-09-09/microvms?token=\uD800`,
  ]) {
    await assert.rejects(
      () => lambdaRequest({
        method: "GET",
        url,
      }),
      /url must not contain invalid UTF-16/
    );
  }
});

test("signing rejects invalid HTTP methods", async () => {
  for (const method of ["", "BAD METHOD", "GET\nX-Test: y", null, 123, Symbol("GET")]) {
    await assert.rejects(
      () => lambdaRequest({
        method,
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      }),
      /method must be a valid HTTP token/
    );
  }
});

test("signing rejects credential components with slash separators", async () => {
  await assert.rejects(
    () => signAwsRequest({
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
    () => lambdaRequest({
      service: "bad/service",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /service must not contain \//
  );
  await assert.rejects(
    () => lambdaRequest({
      region: "bad/region",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /region must not contain \//
  );
});

test("signing rejects credential fields with control characters", async () => {
  await assert.rejects(
    () => signAwsRequest({
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
    () => lambdaRequest({
      sessionToken: "token\r\nvalue",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /sessionToken must not contain control characters/
  );
  await assert.rejects(
    () => lambdaRequest({
      service: "lambda\n",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /service must not contain control characters/
  );
  await assert.rejects(
    () => lambdaRequest({
      region: "ap-northeast-1\u007f",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /region must not contain control characters/
  );
  await assert.rejects(
    () => signAwsRequest({
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

test("signing rejects credential components with whitespace", async () => {
  await assert.rejects(
    () => signAwsRequest({
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
    () => lambdaRequest({
      service: "lambda test",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /service must not contain whitespace/
  );
  await assert.rejects(
    () => lambdaRequest({
      region: "ap northeast-1",
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /region must not contain whitespace/
  );
});

test("signing rejects session tokens with surrounding whitespace", async () => {
  await assert.rejects(
    () => lambdaRequest({
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

test("signing rejects Authorization parameter separators in credential components", async () => {
  for (const [name, value] of [
    ["accessKeyId", "AKID,Injected=x"],
    ["service", "s3,Injected=x"],
    ["region", "us-east-1=Injected"],
    ["service", "lambda;Injected"],
  ]) {
    await assert.rejects(
      () => signAwsRequest({
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
    () => lambdaRequest({
      sessionToken: 123,
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    }),
    /sessionToken must be a non-empty string/
  );
  assert.throws(
    () => new SigV4Client({
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
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: {
        signingDate: FIXED_AMZ_DATE,
        secretAccessKey: "SECRET2",
      },
    }),
    /init\.signing\.secretAccessKey cannot override/
  );
  await assert.rejects(
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: {
        cache: new Map(),
      },
    }),
    /init\.signing\.cache cannot override/
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

test("signing rejects non-boolean signing options", async () => {
  assert.throws(
    () => lambdaClient({ unsignedPayload: "false" }),
    /unsignedPayload must be a boolean/
  );
  await assert.rejects(
    () => lambdaRequest({
      method: "POST",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      body: "{}",
      unsignedPayload: "false",
    }),
    /unsignedPayload must be a boolean/
  );
  const client = lambdaClient();
  await assert.rejects(
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      signing: {
        signAllHeaders: "false",
      },
    }),
    /init\.signing\.signAllHeaders must be a boolean/
  );
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
      connection: "keep-alive",
      "keep-alive": "timeout=5",
      "proxy-authenticate": "Basic",
      "proxy-authorization": "Basic stale",
      te: "trailers",
      trailer: "x-debug",
      "transfer-encoding": "chunked",
      upgrade: "websocket",
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
  const signedRequest = await client.sign(new Request(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  }), { signing: { signingDate: FIXED_AMZ_DATE } });
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

test("SigV4Client rejects GET and HEAD bodies", async () => {
  const client = lambdaClient();
  for (const method of ["GET", "HEAD"]) {
    await assert.rejects(
      () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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

test("unsignableHeaders cannot exclude SigV4 core headers", async () => {
  const signed = await s3Request({
    method: "PUT",
    url: `${S3_ENDPOINT}/example-bucket/core-headers.txt`,
    headers: {
      "x-debug-only": "skip-me",
    },
    body: "hello",
    sessionToken: SESSION_TOKEN,
    unsignableHeaders: [
      "host",
      "x-amz-content-sha256",
      "x-amz-date",
      "x-amz-security-token",
      "x-debug-only",
    ],
  });
  const authorization = signed.headers.get("authorization") || "";
  assert.match(
    authorization,
    /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token/
  );
  assert.doesNotMatch(authorization, /x-debug-only/);
});

test("unsignableHeaders rejects string inputs", async () => {
  const message = /unsignableHeaders must be an iterable of header names/;
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      unsignableHeaders: "x-debug-only",
    }),
    message
  );
  assert.throws(
    () => lambdaClient({ unsignableHeaders: "x-debug-only" }),
    message
  );
  const client = lambdaClient();
  await assert.rejects(
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      unsignableHeaders: null,
    }),
    message
  );
  assert.throws(
    () => lambdaClient({ unsignableHeaders: null }),
    message
  );
  const client = lambdaClient();
  await assert.rejects(
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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

test("SigV4Client snapshots per-request unsignableHeaders iterables", async () => {
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

test("signAwsRequest snapshots one-shot unsignableHeaders iterables", async () => {
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

test("external signing key cache keys do not expose the secret access key", async () => {
  const cache = new Map();
  await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    cache,
  });
  assert.equal(cache.size, 1);
  for (const key of cache.keys()) {
    assert.equal(key.includes(SECRET_ACCESS_KEY), false);
    assert.match(key, /^sigv4,[0-9a-f]{64},20260616,ap-northeast-1,lambda$/);
  }
});

test("signing rejects invalid signing key caches", async () => {
  assert.throws(
    () => lambdaClient({ cache: {} }),
    /cache must be a Map-like cache/
  );
  assert.throws(
    () => lambdaClient({ cache: new WeakMap() }),
    /cache must be a Map-like cache/
  );
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      cache: {},
    }),
    /cache must be a Map-like cache/
  );
  await assert.rejects(
    () => lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      cache: new WeakMap(),
    }),
    /cache must be a Map-like cache/
  );
});

test("SigV4Client computes the secret hash lazily", () => {
  const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  try {
    crypto.subtle.digest = () => {
      throw new Error("digest should not run during construction");
    };
    assert.doesNotThrow(() => lambdaClient());
  } finally {
    crypto.subtle.digest = originalDigest;
  }
});

test("SigV4Client.sign supports FormData bodies", async () => {
  const client = lambdaClient();
  const form = new FormData();
  form.set("message", "hello");
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    body: form,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.match(signed.headers.get("content-type") || "", /^multipart\/form-data; boundary=/);
  assert.match(await signed.clone().text(), /name="message"/);
  assert.match(
    signed.headers.get("authorization") || "",
    /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/
  );
});

test("SigV4Client.sign rejects manual FormData content-type", async () => {
  const client = lambdaClient();
  const form = new FormData();
  form.set("message", "hello");
  for (const contentType of ["multipart/form-data", "multipart/form-data; boundary=manual"]) {
    await assert.rejects(
      () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
        method: "POST",
        headers: {
          "content-type": contentType,
        },
        body: form,
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
      /FormData content-type must be generated by the runtime/
    );
  }
});

test("S3 unsigned FormData rejects manual content-type", async () => {
  const client = s3Client();
  const form = new FormData();
  form.set("message", "hello");
  await assert.rejects(
    () => client.sign(`${S3_ENDPOINT}/example-bucket/form-data.txt`, {
      method: "PUT",
      headers: {
        "content-type": "multipart/form-data; boundary=manual",
      },
      body: form,
      signing: { signingDate: FIXED_AMZ_DATE },
    }),
    /FormData content-type must be generated by the runtime/
  );
});

test("SigV4Client.sign supports ReadableStream bodies", async () => {
  const client = lambdaClient();
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
    method: "POST",
    body,
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(await signed.clone().text(), "hello");
  assert.match(signed.headers.get("authorization") || "", /SignedHeaders=host;x-amz-content-sha256;x-amz-date/);
});

test("SigV4Client.sign does not fully buffer unsigned S3 Request streams", async () => {
  let pulls = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode(String(pulls)));
      if (pulls === 3) controller.close();
    },
  });
  const request = new Request(`${S3_ENDPOINT}/example-bucket/large-upload.bin`, {
    method: "PUT",
    body,
    duplex: "half",
  });
  const client = s3Client();
  const signed = await client.sign(request, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.ok(pulls < 3);
  assert.equal(signed.headers.get("x-amz-content-sha256"), "UNSIGNED-PAYLOAD");
  assert.equal(await signed.text(), "123");
  assert.equal(pulls, 3);
});

test("SigV4Client rejects dot-segment string URLs", async () => {
  const client = s3Client();
  for (const segment of ["..", "%2e%2e", ".%2e", "%2e.", ".%2E", "%2E."]) {
    await assert.rejects(
      () => client.sign(`${S3_ENDPOINT}/example-bucket/a/${segment}/b.txt`, {
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
      /cannot represent s3 URLs with dot segments/
    );
  }
  await assert.rejects(
    () => client.sign("https://lambda.us-east-1.amazonaws.com/a/../b", {
      signing: { service: "lambda", region: "us-east-1", signingDate: FIXED_AMZ_DATE },
    }),
    /cannot represent lambda URLs with dot segments/
  );
});

test("SigV4Client rejects dot-segment URLs before reading stream bodies", async () => {
  let pulls = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode(String(pulls)));
      if (pulls === 3) controller.close();
    },
  });
  const client = lambdaClient();
  await assert.rejects(
    () => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/a/../microvms`, {
      method: "POST",
      body,
      signing: { signingDate: FIXED_AMZ_DATE },
    }),
    /cannot represent lambda URLs with dot segments/
  );
  assert.ok(pulls < 3);
});

test("SigV4Client.fetch rejects dot-segment URLs before reading stream bodies", async () => {
  let pulls = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode(String(pulls)));
      if (pulls === 3) controller.close();
    },
  });
  const client = lambdaClient({
    fetch: async () => new Response("should not fetch"),
  });
  await assert.rejects(
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/a/../microvms`, {
      method: "PUT",
      body,
      signing: { signingDate: FIXED_AMZ_DATE },
    }),
    /cannot represent lambda URLs with dot segments/
  );
  assert.ok(pulls < 3);
});

test("SigV4Client.fetch does not fully buffer unsigned S3 Request streams by default", async () => {
  let pulls = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode(String(pulls)));
      if (pulls === 3) controller.close();
    },
  });
  const request = new Request(`${S3_ENDPOINT}/example-bucket/large-upload.bin`, {
    method: "PUT",
    body,
    duplex: "half",
  });
  const client = s3Client({
    fetch: async (signed) => {
      assert.ok(pulls < 3);
      assert.equal(signed.headers.get("x-amz-content-sha256"), "UNSIGNED-PAYLOAD");
      assert.equal(await signed.text(), "123");
      return new Response("ok");
    },
  });
  const response = await client.fetch(request, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  assert.equal(response.status, 200);
  assert.equal(pulls, 3);
});

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

test("SigV4Client rejects non-function fetch options", () => {
  for (const fetch of [null, false, 0]) {
    assert.throws(
      () => lambdaClient({ fetch }),
      /fetch must be a function/
    );
  }
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

test("SigV4Client.fetch retries transient fetch rejections", async () => {
  let calls = 0;
  const client = lambdaClient({
    retries: 1,
    initialRetryDelayMs: 0,
    fetch: async () => {
      calls += 1;
      if (calls === 1) throw new TypeError("socket reset");
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
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
      method: "PUT",
      signal: controller.signal,
      signing: { signingDate: FIXED_AMZ_DATE },
    }),
    /aborted/
  );
  assert.equal(calls, 1);
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
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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
      return new Response(new ReadableStream({
        start(innerController) {
          innerController.enqueue(new TextEncoder().encode("retry"));
        },
        cancel() {
          cancelled += 1;
        },
      }), { status: 500 });
    },
  });
  await assert.rejects(
    () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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
  const response = await client.fetch(new Request(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: "{}",
  }), {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
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
        return new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("retry"));
          },
          cancel() {
            cancelled += 1;
          },
        }), { status: 500 });
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
    globalThis.setTimeout = ((callback, delay) => {
      delays.push(delay);
      callback();
      return 0;
    });
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

test("SigV4Client rejects negative retries", () => {
  assert.throws(
    () => lambdaClient({
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
      () => client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
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

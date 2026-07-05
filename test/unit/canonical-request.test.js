// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { test } from "node:test";

import { signAwsRequest } from "../../dist/index.js";

import {
  ACCESS_KEY_ID,
  AWS_S3_EXAMPLE_AMZ_DATE,
  AWS_S3_HEADER_AUTH_FIXTURES,
  EXECUTE_API_ENDPOINT,
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  S3_FIXTURES,
  SECRET_ACCESS_KEY,
  SESSION_TOKEN,
  assertHelloStreamReadable,
  awsS3ExampleRequest,
  executeApiClient,
  executeApiRequest,
  helloStream,
  lambdaRequest,
  s3Client,
  s3Request,
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

test("canonical query decodes percent-encoded unreserved bytes", async () => {
  const base = {
    method: "GET",
  };
  const signedEncoded = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?marker=%7e&letter=%41`,
  });
  const signedLiteral = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?marker=~&letter=A`,
  });
  assert.equal(signedEncoded.headers.get("authorization"), signedLiteral.headers.get("authorization"));
  assert.equal(
    signedEncoded.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=f3c325ba6f2e2bd970c2f6e1ecff4e0d32f2cfaf6393ecc7d02e3a3b45329091"
  );
});

test("canonical query normalizes percent-encoded hex case", async () => {
  const base = {
    method: "GET",
  };
  const signedLowercaseHex = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?prefix=a%2fb`,
  });
  const signedUppercaseHex = await lambdaRequest({
    ...base,
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms?prefix=a%2Fb`,
  });
  assert.equal(signedLowercaseHex.headers.get("authorization"), signedUppercaseHex.headers.get("authorization"));
  assert.equal(
    signedLowercaseHex.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=0c1b0bb065e448519779b6c939d4d19e0cf6d1ccd286bac4d6e030d3959a0a02"
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
  assert.notEqual(signedInvalidUtf8.headers.get("authorization"), signedEscapedPercent.headers.get("authorization"));
  assert.equal(
    signedInvalidUtf8.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=aedf3e5cca7c3a453cedfdd3496480941863cc2b54981f06485fb52324ed89a4"
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
  assert.notEqual(signedEmptyKey.headers.get("authorization"), signedWithoutEmptyKey.headers.get("authorization"));
  assert.equal(
    signedEmptyKey.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=945bbf0579973ac76b9a112d4278623fbc7a41981e39fbc28f5a8f47829ac9f0"
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
  assert.equal(signedEmptyMiddle.headers.get("authorization"), signedNoEmptyMiddle.headers.get("authorization"));
  assert.equal(signedLeadingEmpty.headers.get("authorization"), signedNoEmpty.headers.get("authorization"));
  assert.equal(signedTrailingEmpty.headers.get("authorization"), signedNoEmpty.headers.get("authorization"));
  assert.equal(signedLeadingEmpty.headers.get("authorization"), signedTrailingEmpty.headers.get("authorization"));
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
  assert.equal(signedLiteralPlus.headers.get("authorization"), signedEncodedPlus.headers.get("authorization"));
  assert.equal(
    signedLiteralPlus.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=6f55d540120000c262d6a11e63797bb2cfea0984c7fb40c0b105756e26fdcb28"
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
  assert.notEqual(signedEncodedSlash.headers.get("authorization"), signedPathSlash.headers.get("authorization"));
  assert.equal(
    signedEncodedSlash.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=672527e0b777d6984e5fecdb95351f933b8d725ab7a511f0af342d9a46534d81"
  );
});

test("canonical S3 paths preserve encoded unreserved bytes", async () => {
  const signedEncodedTilde = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/my%7Efile.txt`,
  });
  const signedLiteralTilde = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/my~file.txt`,
  });
  const signedEncodedLetter = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/%41.txt`,
  });
  const signedLiteralLetter = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/A.txt`,
  });
  assert.equal(
    signedEncodedTilde.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=14f848760fef301c5dd9c5fd5d5096989f196be87ed942a3f9d3b9c0a3199eda"
  );
  assert.notEqual(signedEncodedTilde.headers.get("authorization"), signedLiteralTilde.headers.get("authorization"));
  assert.equal(
    signedEncodedLetter.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=5da5a18bc3ad5521dc60afe7630eae9314577accf1f24822b76b54e44e2af194"
  );
  assert.notEqual(signedEncodedLetter.headers.get("authorization"), signedLiteralLetter.headers.get("authorization"));
});

test("canonical S3 paths preserve percent-encoded hex case", async () => {
  const signedLowercaseHex = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/my%2bfolder/file.txt`,
  });
  const signedUppercaseHex = await s3Request({
    method: "GET",
    url: `${S3_ENDPOINT}/example-bucket/my%2Bfolder/file.txt`,
  });
  assert.equal(
    signedLowercaseHex.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=01c504190d0feedaceeb52da046a73d5695d03d9e95d8dc4ea10bae5b17c4985"
  );
  assert.notEqual(signedLowercaseHex.headers.get("authorization"), signedUppercaseHex.headers.get("authorization"));
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
  assert.notEqual(signedLiteralDotSegment.headers.get("authorization"), signedNormalized.headers.get("authorization"));
  assert.notEqual(signedEncodedDotSegment.headers.get("authorization"), signedNormalized.headers.get("authorization"));
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
  assert.equal(signedDefaultPort.url, "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms?=v");
  assert.equal(signedDefaultPort.headers.get("authorization"), signedWithoutDefaultPort.headers.get("authorization"));
});

test("string URL signing includes non-default ports in host", async () => {
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}:9443/2025-09-09/microvms`,
  });
  assert.equal(signed.headers.get("host"), "lambda.ap-northeast-1.amazonaws.com:9443");
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/lambda/aws4_request, SignedHeaders=host;x-amz-date, Signature=5f9d64da8d19fcc1ef0e28a8dffb9a120f0dbfba820e5303b76551357d42785e"
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

test("doubleUrlEncode double-escapes non-S3 canonical path bytes", async () => {
  const url = `${EXECUTE_API_ENDPOINT}/prod/my+folder/a%2Fb/%7E`;
  const signedDefault = await executeApiRequest({
    method: "GET",
    url,
  });
  const signedDoubleEncoded = await executeApiRequest({
    method: "GET",
    url,
    doubleUrlEncode: true,
  });
  assert.equal(
    signedDefault.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=5ae33dd5d01776fcb1fb836dd84c6e28d168b21da37ab3506624ec211dfc9c7c"
  );
  assert.equal(
    signedDoubleEncoded.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=7635698892bbcc2d515044be999eaba42348d3b1ec8b78436b7cc0da8cc0a5ac"
  );
});

test("doubleUrlEncode distinguishes literal plus from an encoded plus byte", async () => {
  const signedLiteralPlus = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/my+folder/file.txt`,
    doubleUrlEncode: true,
  });
  const signedEncodedPlus = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/my%2Bfolder/file.txt`,
    doubleUrlEncode: true,
  });
  assert.equal(
    signedLiteralPlus.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=7ba4625b596ebe31fa2c3f7a79b2f2c8eadc98ecea15a82ec819d15b6efbab2a"
  );
  assert.equal(
    signedEncodedPlus.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=09284d1e5eee0d09f4c339b6143ee444a6c6d5209c4fef9285757de9bc10f02e"
  );
  assert.notEqual(signedLiteralPlus.headers.get("authorization"), signedEncodedPlus.headers.get("authorization"));
});

test("doubleUrlEncode encodes literal sub-delimiters once", async () => {
  const signed = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/a=b&c/d`,
    doubleUrlEncode: true,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=34057f1b4cbc44a331d5f01379667ce237f2822cc106569ebe47cd0ada9a451b"
  );
});

test("doubleUrlEncode preserves percent-encoded hex case", async () => {
  const signedLowercaseHex = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/u/%2fpath`,
    doubleUrlEncode: true,
  });
  const signedUppercaseHex = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/u/%2Fpath`,
    doubleUrlEncode: true,
  });
  assert.equal(
    signedLowercaseHex.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=899b842d343860ae1abc9439a9364547415fa92aa679f680e5f5636973b46d24"
  );
  assert.equal(
    signedUppercaseHex.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=a06a8e197c49f0e572815bbd119335cc3e6a049673faf5d4f59898ce4a495357"
  );
  assert.notEqual(signedLowercaseHex.headers.get("authorization"), signedUppercaseHex.headers.get("authorization"));
});

test("doubleUrlEncode leaves canonical query encoding single-escaped", async () => {
  const signed = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/my+folder/file.txt?prefix=a%2Fb&marker=x+y`,
    doubleUrlEncode: true,
  });
  assert.equal(
    signed.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=a22882241e6624b702b760f316e3cc51924f84ce8b15a3eeb819fe242cef4a87"
  );
});

test("doubleUrlEncode rejects non-S3 dot path segments", async () => {
  for (const path of ["/prod/a/../b/./c", "/prod/a/b/..", "/prod/a/%2E%2E/b"]) {
    await assert.rejects(
      () =>
        executeApiRequest({
          method: "GET",
          url: `${EXECUTE_API_ENDPOINT}${path}`,
          doubleUrlEncode: true,
        }),
      /non-S3 doubleUrlEncode URLs must not contain dot path segments/
    );
  }
});

test("doubleUrlEncode rejects non-S3 dot path segments before reading stream bodies", async () => {
  const body = helloStream();
  await assert.rejects(
    () =>
      executeApiRequest({
        method: "POST",
        url: `${EXECUTE_API_ENDPOINT}/prod/a/../b`,
        body,
        doubleUrlEncode: true,
      }),
    /non-S3 doubleUrlEncode URLs must not contain dot path segments/
  );
  await assertHelloStreamReadable(body);
});

test("doubleUrlEncode collapses repeated slashes in non-S3 canonical paths", async () => {
  const signedRepeatedSlashes = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod//resources///v2/`,
    doubleUrlEncode: true,
  });
  const signedNormalized = await executeApiRequest({
    method: "GET",
    url: `${EXECUTE_API_ENDPOINT}/prod/resources/v2/`,
    doubleUrlEncode: true,
  });
  assert.equal(
    signedRepeatedSlashes.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=4240e1d62558f87a6bd2646f0c7342e8f11b8c4263e89c95334dfaf2874fa13b"
  );
  assert.equal(signedRepeatedSlashes.headers.get("authorization"), signedNormalized.headers.get("authorization"));
});

test("SigV4Client doubleUrlEncode default can be overridden per request", async () => {
  const url = `${EXECUTE_API_ENDPOINT}/prod/my+folder/a%2Fb/%7E`;
  const client = executeApiClient({
    doubleUrlEncode: true,
  });
  const signedDefault = await client.sign(url, {
    signing: { signingDate: FIXED_AMZ_DATE },
  });
  const signedOverride = await client.sign(url, {
    signing: { signingDate: FIXED_AMZ_DATE, doubleUrlEncode: false },
  });
  assert.equal(
    signedDefault.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=7635698892bbcc2d515044be999eaba42348d3b1ec8b78436b7cc0da8cc0a5ac"
  );
  assert.equal(
    signedOverride.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/ap-northeast-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=5ae33dd5d01776fcb1fb836dd84c6e28d168b21da37ab3506624ec211dfc9c7c"
  );
});

test("S3 keeps single-encoded path semantics by default but can opt into doubleUrlEncode", async () => {
  const url = `${S3_ENDPOINT}/example-bucket/my+folder/a%2Fb/%7E`;
  const signedDefault = await s3Request({
    method: "GET",
    url,
  });
  const signedDoubleEncoded = await s3Request({
    method: "GET",
    url,
    doubleUrlEncode: true,
  });
  assert.notEqual(signedDefault.headers.get("authorization"), signedDoubleEncoded.headers.get("authorization"));
  assert.equal(
    signedDoubleEncoded.headers.get("authorization"),
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=1c263cb8648e185d798d86901cda77513e4972474a2838afb79be85b2c5a0918"
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
  assert.equal(signedRepeatedSlash.url, "https://lambda.ap-northeast-1.amazonaws.com/2025-09-09//microvms");
  assert.notEqual(signedRepeatedSlash.headers.get("authorization"), signedSingleSlash.headers.get("authorization"));
});

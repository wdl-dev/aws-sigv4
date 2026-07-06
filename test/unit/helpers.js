// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";

import { SigV4Client, signAwsRequest } from "../../dist/index.js";

export const ACCESS_KEY_ID = "AKIDEXAMPLE";
export const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
export const SESSION_TOKEN = "session-token-example";
export const FIXED_AMZ_DATE = "20260616T010203Z";
export const LAMBDA_ENDPOINT = "https://lambda.ap-northeast-1.amazonaws.com";
export const EXECUTE_API_ENDPOINT = "https://abc123.execute-api.ap-northeast-1.amazonaws.com";
export const S3_ENDPOINT = "https://s3.us-east-1.amazonaws.com";
export const AWS_S3_EXAMPLE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
export const AWS_S3_EXAMPLE_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
export const AWS_S3_EXAMPLE_AMZ_DATE = "20130524T000000Z";
export const AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export const AWS_S3_EXAMPLE_ENDPOINT = "https://examplebucket.s3.amazonaws.com";

export function lambdaClient(options = {}) {
  return new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    ...options,
  });
}

export function executeApiClient(options = {}) {
  return new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "execute-api",
    region: "ap-northeast-1",
    ...options,
  });
}

export function s3Client(options = {}) {
  return new SigV4Client({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
    ...options,
  });
}

export function lambdaRequest(options) {
  return signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    signingDate: FIXED_AMZ_DATE,
    ...options,
  });
}

export function executeApiRequest(options) {
  return signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "execute-api",
    region: "ap-northeast-1",
    signingDate: FIXED_AMZ_DATE,
    ...options,
  });
}

export function s3Request(options) {
  return signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
    signingDate: FIXED_AMZ_DATE,
    ...options,
  });
}

export function awsS3ExampleRequest(options) {
  return signAwsRequest({
    accessKeyId: AWS_S3_EXAMPLE_ACCESS_KEY_ID,
    secretAccessKey: AWS_S3_EXAMPLE_SECRET_ACCESS_KEY,
    service: "s3",
    region: "us-east-1",
    signingDate: AWS_S3_EXAMPLE_AMZ_DATE,
    ...options,
  });
}

export function helloStream() {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
}

export async function assertHelloStreamReadable(body) {
  assert.equal(body.locked, false);
  assert.equal(await new Response(body).text(), "hello");
}

export async function assertFetchRejectsBeforeBody(clientOptions, fetchArgs, expectedError) {
  let calls = 0;
  const body = helloStream();
  const client = lambdaClient({
    ...clientOptions,
    retries: 1,
    fetch: async () => {
      calls += 1;
      return new Response("unreachable");
    },
  });
  const {
    input = `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    init = {},
    assertBodyReadable = () => assertHelloStreamReadable(body),
  } = fetchArgs(body);
  await assert.rejects(() => client.fetch(input, init), expectedError);
  assert.equal(calls, 0);
  await assertBodyReadable();
}

export const AWS_S3_HEADER_AUTH_FIXTURES = [
  {
    name: "GET object with range",
    method: "GET",
    url: `${AWS_S3_EXAMPLE_ENDPOINT}/test.txt`,
    headers: {
      range: "bytes=0-9",
      "x-amz-content-sha256": AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
    },
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
    expectedContentSha256: AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
  },
  {
    name: "PUT object with reduced redundancy storage",
    method: "PUT",
    url: `${AWS_S3_EXAMPLE_ENDPOINT}/test$file.text`,
    headers: {
      date: "Fri, 24 May 2013 00:00:00 GMT",
      "x-amz-storage-class": "REDUCED_REDUNDANCY",
      "x-amz-content-sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
    },
    body: new TextEncoder().encode("Welcome to Amazon S3."),
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
    expectedContentSha256: "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
  },
  {
    name: "GET bucket lifecycle",
    method: "GET",
    url: `${AWS_S3_EXAMPLE_ENDPOINT}/?lifecycle`,
    headers: {
      "x-amz-content-sha256": AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
    },
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
    expectedContentSha256: AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
  },
  {
    name: "GET bucket with max-keys and prefix",
    method: "GET",
    url: `${AWS_S3_EXAMPLE_ENDPOINT}/?max-keys=2&prefix=J`,
    headers: {
      "x-amz-content-sha256": AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
    },
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
    expectedContentSha256: AWS_S3_EXAMPLE_EMPTY_PAYLOAD_HASH,
  },
];

export const S3_FIXTURES = [
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
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-color, Signature=e815879fb7e43ffa6defedacb4cbaa791e3d7d44edbff342ddc5b6b8cfbdaece",
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
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-checksum-sha256;x-amz-content-sha256;x-amz-date, Signature=b4352c2e0906d0a76dcc8b28c839b72629870b321e80dda6fff9b4c066d52910",
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
    expectedAuthorization:
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=0cc131c1da50954868d149555460960971cfae3822c6b2cf6984925a04ff5d10",
    expectedContentSha256: "UNSIGNED-PAYLOAD",
    expectedSecurityToken: SESSION_TOKEN,
    expectedUrl: `${S3_ENDPOINT}/example-bucket/objects/session.txt`,
  },
];

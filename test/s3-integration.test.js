// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import { SigV4Client } from "../dist/index.js";

const enabled = process.env.AWS_SIGV4_S3_INTEGRATION === "1";
const endpoint = stripTrailingSlash(process.env.AWS_SIGV4_S3_ENDPOINT || "http://127.0.0.1:19500");
const accessKeyId = process.env.AWS_SIGV4_S3_ACCESS_KEY_ID || "test";
const secretAccessKey = process.env.AWS_SIGV4_S3_SECRET_ACCESS_KEY || "test";
const region = process.env.AWS_SIGV4_S3_REGION || "us-east-1";

test("S3-compatible integration signs bucket and object operations", { skip: enabled ? false : "set AWS_SIGV4_S3_INTEGRATION=1" }, async () => {
  const bucket = `aws-sigv4-${randomUUID()}`;
  const key = "objects/hello+sigv4.txt";
  const body = `hello from aws-sigv4 ${randomUUID()}`;
  const s3 = new SigV4Client({
    accessKeyId,
    secretAccessKey,
    service: "s3",
    region,
    retries: 1,
  });

  await expectOk(
    s3.fetch(`${endpoint}/${bucket}`, {
      method: "PUT",
    }),
    "create bucket"
  );

  try {
    await expectOk(
      s3.fetch(`${endpoint}/${bucket}/${key}`, {
        method: "PUT",
        headers: {
          "content-type": "text/plain",
        },
        body,
      }),
      "put object"
    );

    const getObject = await expectOk(
      s3.fetch(`${endpoint}/${bucket}/${key}`, {
        method: "GET",
      }),
      "get object"
    );
    assert.equal(await getObject.text(), body);

    const listBucket = await expectOk(
      s3.fetch(`${endpoint}/${bucket}?list-type=2&prefix=objects/hello%2B`, {
        method: "GET",
      }),
      "list bucket"
    );
    assert.match(await listBucket.text(), /hello\+sigv4\.txt/);
  } finally {
    await s3.fetch(`${endpoint}/${bucket}/${key}`, { method: "DELETE" }).catch(() => {});
    await s3.fetch(`${endpoint}/${bucket}`, { method: "DELETE" }).catch(() => {});
  }
});

async function expectOk(responsePromise, operation) {
  const response = await responsePromise;
  if (response.ok) return response;
  const text = await response.text();
  assert.fail(`${operation} failed with ${response.status}: ${text}`);
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/u, "");
}

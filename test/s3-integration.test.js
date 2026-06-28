// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { test } from "node:test";

import { SigV4Client } from "../dist/index.js";

const integration = process.env.AWS_SIGV4_S3_INTEGRATION;
const enabled = integration === "1" || integration === "s3mock" || integration === "aws";
const endpoint = (process.env.AWS_SIGV4_S3_ENDPOINT || "http://127.0.0.1:19500").replace(/\/+$/u, "");
const accessKeyId = process.env.AWS_SIGV4_S3_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID || "test";
const secretAccessKey = process.env.AWS_SIGV4_S3_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY || "test";
const sessionToken = process.env.AWS_SIGV4_S3_SESSION_TOKEN || process.env.AWS_SESSION_TOKEN || undefined;
const region = process.env.AWS_SIGV4_S3_REGION || "us-east-1";
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const requestTimeoutMs = parseTimeoutMs(process.env.AWS_SIGV4_S3_REQUEST_TIMEOUT_MS);
const existingBucket = process.env.AWS_SIGV4_S3_BUCKET || undefined;

test(
  "S3-compatible integration signs bucket and object operations",
  { skip: enabled ? false : "set AWS_SIGV4_S3_INTEGRATION=1, s3mock, or aws", timeout: 240_000 },
  async () => {
    if (integration === "aws" && existingBucket === undefined) {
      assert.fail("AWS_SIGV4_S3_BUCKET is required when AWS_SIGV4_S3_INTEGRATION=aws");
    }
    const runId = randomUUID();
    const bucket = existingBucket ?? `aws-sigv4-${runId}`;
    const keyPrefix = existingBucket === undefined ? "" : `runs/${runId}/`;
    const keySuffix = "sigv4.txt";
    const key = `${keyPrefix}objects/hello+${keySuffix}`;
    const objectUrl = `${endpoint}/${bucket}/${encodeS3KeyPath(key)}`;
    const listPrefix = key.slice(0, key.length - keySuffix.length);
    const body = `hello from aws-sigv4 ${randomUUID()}`;
    const s3 = new SigV4Client({
      accessKeyId,
      secretAccessKey,
      sessionToken,
      service: "s3",
      region,
      retries: 1,
    });
    let bucketCreated = false;

    try {
      if (existingBucket === undefined) {
        await expectOk(
          s3.fetch(`${endpoint}/${bucket}`, {
            method: "PUT",
            signal: requestSignal(),
          }),
          "create bucket"
        );
        bucketCreated = true;
      }

      try {
        await expectOk(
          s3.fetch(objectUrl, {
            method: "PUT",
            headers: {
              "content-type": "text/plain",
            },
            body,
            signal: requestSignal(),
          }),
          "put object"
        );

        const getObject = await expectOk(
          s3.fetch(objectUrl, {
            method: "GET",
            signal: requestSignal(),
          }),
          "get object"
        );
        assert.equal(await getObject.text(), body);

        const listBucket = await expectOk(
          s3.fetch(
            `${endpoint}/${bucket}?${new URLSearchParams({ "list-type": "2", prefix: listPrefix }).toString()}`,
            {
              method: "GET",
              signal: requestSignal(),
            }
          ),
          "list bucket"
        );
        const listText = await listBucket.text();
        assert.match(listText, /<ListBucketResult\b/);
        assert.match(listText, new RegExp(`<Prefix>${escapeRegExp(listPrefix)}</Prefix>`));
        assert.match(listText, /<KeyCount>1<\/KeyCount>/);
        assert.equal((listText.match(/<Contents>/gu) || []).length, 1);
        assert.match(listText, new RegExp(`<Key>${escapeRegExp(key)}</Key>`));
      } finally {
        await s3.fetch(objectUrl, { method: "DELETE", signal: requestSignal() }).catch(() => {});
      }
    } finally {
      if (bucketCreated) {
        await s3.fetch(`${endpoint}/${bucket}`, { method: "DELETE", signal: requestSignal() }).catch(() => {});
      }
    }
  }
);

function encodeS3KeyPath(key) {
  return key.split("/").map(encodeURIComponent).join("/");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

async function expectOk(responsePromise, operation) {
  const response = await responsePromise;
  if (response.ok) {
    return response;
  }
  const text = await response.text();
  assert.fail(`${operation} failed with ${response.status}: ${text}`);
}

function requestSignal() {
  return AbortSignal.timeout(requestTimeoutMs);
}

function parseTimeoutMs(value) {
  if (value === undefined || value === "") {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0 || ms > Number.MAX_SAFE_INTEGER) {
    return DEFAULT_REQUEST_TIMEOUT_MS;
  }
  return Math.trunc(ms);
}

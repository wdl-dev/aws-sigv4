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
  "S3-compatible integration signs bucket, object, and reserved-key operations",
  { skip: enabled ? false : "set AWS_SIGV4_S3_INTEGRATION=1, s3mock, or aws", timeout: 240_000 },
  async () => {
    if (integration === "aws" && existingBucket === undefined) {
      assert.fail("AWS_SIGV4_S3_BUCKET is required when AWS_SIGV4_S3_INTEGRATION=aws");
    }
    const runId = randomUUID();
    const bucket = existingBucket ?? `aws-sigv4-${runId}`;
    const keyPrefix = existingBucket === undefined ? "" : `runs/${runId}/`;
    const keySuffix = "sigv4.txt";
    const keys = [
      `${keyPrefix}objects/hello+${keySuffix}`,
      `${keyPrefix}objects/report(final).txt`,
      `${keyPrefix}objects/a:b,c!.txt`,
    ];
    const objects = keys.map((key) => ({
      key,
      url: `${endpoint}/${bucket}/${encodeS3KeyPath(key)}`,
      body: `hello from aws-sigv4 ${randomUUID()}`,
    }));
    const listPrefix = `${keyPrefix}objects/`;
    const s3 = new SigV4Client({
      accessKeyId,
      secretAccessKey,
      sessionToken,
      service: "s3",
      region,
      retries: 1,
    });
    let bucketCreated = false;
    const objectUrlsToCleanup = [];
    let primaryError;
    const cleanupErrors = [];

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

      for (const object of objects) {
        objectUrlsToCleanup.push(object.url);
        await expectOk(
          s3.fetch(object.url, {
            method: "PUT",
            headers: {
              "content-type": "text/plain",
            },
            body: object.body,
            signal: requestSignal(),
          }),
          `put object ${object.key}`
        );

        const getObject = await expectOk(
          s3.fetch(object.url, {
            method: "GET",
            signal: requestSignal(),
          }),
          `get object ${object.key}`
        );
        assert.equal(await getObject.text(), object.body);
      }

      const listBucket = await expectOk(
        s3.fetch(`${endpoint}/${bucket}?${new URLSearchParams({ "list-type": "2", prefix: listPrefix }).toString()}`, {
          method: "GET",
          signal: requestSignal(),
        }),
        "list bucket"
      );
      const listText = await listBucket.text();
      assert.match(listText, /<ListBucketResult\b/);
      assert.match(listText, new RegExp(`<Prefix>${escapeRegExp(listPrefix)}</Prefix>`));
      assert.match(listText, new RegExp(`<KeyCount>${objects.length}</KeyCount>`));
      assert.equal((listText.match(/<Contents>/gu) || []).length, objects.length);
      for (const object of objects) {
        assert.match(listText, new RegExp(`<Key>${escapeRegExp(object.key)}</Key>`));
      }
    } catch (err) {
      primaryError = err;
    } finally {
      for (const objectUrl of objectUrlsToCleanup) {
        await collectCleanupError(cleanupErrors, () =>
          expectOk(s3.fetch(objectUrl, { method: "DELETE", signal: requestSignal() }), "delete object")
        );
      }
      if (bucketCreated) {
        await collectCleanupError(cleanupErrors, () =>
          expectOk(s3.fetch(`${endpoint}/${bucket}`, { method: "DELETE", signal: requestSignal() }), "delete bucket")
        );
      }
      throwIntegrationErrors(primaryError, cleanupErrors);
    }
  }
);

async function collectCleanupError(errors, cleanup) {
  try {
    await cleanup();
  } catch (err) {
    errors.push(err);
  }
}

function throwIntegrationErrors(primaryError, cleanupErrors) {
  if (primaryError !== undefined) {
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [primaryError, ...cleanupErrors],
        "S3-compatible integration failed and cleanup also failed"
      );
    }
    throw primaryError;
  }
  if (cleanupErrors.length === 1) {
    throw cleanupErrors[0];
  }
  if (cleanupErrors.length > 1) {
    throw new AggregateError(cleanupErrors, "S3-compatible integration cleanup failed");
  }
}

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

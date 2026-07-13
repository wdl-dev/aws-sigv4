// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import { signAwsRequest } from "../../dist/index.js";

import { ACCESS_KEY_ID, FIXED_AMZ_DATE, LAMBDA_ENDPOINT, SECRET_ACCESS_KEY, lambdaRequest } from "./helpers.js";

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

test("default signingDate is captured after body preparation", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-06-16T01:02:01Z") });
  const body = new ReadableStream({
    pull(controller) {
      t.mock.timers.setTime(new Date("2026-06-16T01:02:03Z").getTime());
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const signed = await signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    method: "POST",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    body,
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
});

test("null signingDate uses the default clock", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: new Date("2026-06-16T01:02:03Z") });
  const signed = await lambdaRequest({
    method: "GET",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate: null,
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
});

test("explicit signingDate Date objects are captured before body preparation", async () => {
  const signingDate = new Date("2026-06-16T01:02:03.000Z");
  const body = new ReadableStream({
    pull(controller) {
      signingDate.setTime(Date.UTC(2027, 0, 1, 0, 0, 0));
      controller.enqueue(new TextEncoder().encode("hello"));
      controller.close();
    },
  });
  const signed = await signAwsRequest({
    accessKeyId: ACCESS_KEY_ID,
    secretAccessKey: SECRET_ACCESS_KEY,
    service: "lambda",
    region: "ap-northeast-1",
    method: "POST",
    url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    signingDate,
    body,
  });
  assert.equal(signed.headers.get("x-amz-date"), FIXED_AMZ_DATE);
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

  for (const [signingDate, expectedAmzDate] of [
    ["2024-02-29T12:34:56Z", "20240229T123456Z"],
    ["0999-01-02T03:04:05Z", "09990102T030405Z"],
    ["2026-06-16T01:02:03.987Z", FIXED_AMZ_DATE],
  ]) {
    const signed = await lambdaRequest({
      method: "GET",
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
      signingDate,
    });
    assert.equal(signed.headers.get("x-amz-date"), expectedAmzDate, signingDate);
  }
});

test("signingDate rejects ISO-8601 strings without timezone", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: "2026-06-16T01:02:03",
      }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects non-ISO strings with timezone suffixes", async () => {
  await assert.rejects(
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: "06/16/2026 01:02:03 +00:00",
      }),
    /signingDate must be a valid Date/
  );
});

test("signingDate rejects invalid compact AWS date strings", async () => {
  for (const signingDate of ["20269999T999999Z", "20260229T010203Z"]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
          signingDate,
        }),
      /signingDate must be a valid Date/
    );
  }
});

test("signingDate rejects invalid ISO calendar dates", async () => {
  for (const signingDate of ["2026-02-30T00:00:00Z", "2026-04-31T00:00:00Z", "2027-02-29T00:00:00Z"]) {
    await assert.rejects(
      () =>
        lambdaRequest({
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
    () =>
      lambdaRequest({
        method: "GET",
        url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        signingDate: {},
      }),
    /signingDate must be a valid Date/
  );
});

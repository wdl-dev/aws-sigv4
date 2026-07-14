// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  FIXED_AMZ_DATE,
  LAMBDA_ENDPOINT,
  S3_ENDPOINT,
  assertHelloStreamReadable,
  helloStream,
  lambdaClient,
  lambdaRequest,
  s3Client,
} from "./helpers.js";

test("SigV4Client does not replace explicitly invalid duplex values", async () => {
  const body = new ReadableStream({
    start(controller) {
      controller.close();
    },
  });
  await assert.rejects(
    () =>
      s3Client().sign(`${S3_ENDPOINT}/example-bucket/duplex.txt`, {
        method: "PUT",
        body,
        duplex: "bogus",
        signing: { signingDate: FIXED_AMZ_DATE },
      }),
    /bogus.*half/iu
  );
});

test("signing rejects invalid falsy headers instead of treating them as absent", async () => {
  let fetchCalls = 0;
  const client = lambdaClient({
    fetch: async () => {
      fetchCalls += 1;
      return new Response("unreachable");
    },
  });
  const request = new Request(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`);
  for (const headers of [null, false, 0, ""]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          method: "GET",
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
          headers,
        }),
      TypeError
    );
    await assert.rejects(
      () =>
        client.sign(request, {
          headers,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      TypeError
    );
    await assert.rejects(
      () =>
        client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          headers,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      TypeError
    );
  }
  assert.equal(fetchCalls, 0);
});

test("SigV4Client follows the Web IDL RequestInit object boundary", async () => {
  const client = lambdaClient();
  const signed = await client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, null);
  assert.equal(signed.method, "GET");
  for (const init of [false, 0, ""]) {
    await assert.rejects(() => client.sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, init), /init must be an object/);
  }
});

test("signing rejects invalid HTTP methods", async () => {
  for (const method of ["", "BAD METHOD", "GET\nX-Test: y", null, 123, Symbol("GET")]) {
    await assert.rejects(
      () =>
        lambdaRequest({
          method,
          url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
        }),
      /method must be a valid HTTP token/
    );
  }
});

test("SigV4Client rejects Fetch-forbidden methods before consuming bodies", async () => {
  for (const method of ["CONNECT", "TRACE", "TRACK"]) {
    const signBody = helloStream();
    await assert.rejects(
      () =>
        lambdaClient().sign(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          method,
          body: signBody,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      new RegExp(`Fetch-forbidden method ${method}`)
    );
    await assertHelloStreamReadable(signBody);

    let fetchCalls = 0;
    const fetchBody = helloStream();
    const client = lambdaClient({
      fetch: async () => {
        fetchCalls += 1;
        return new Response("unreachable");
      },
    });
    await assert.rejects(
      () =>
        client.fetch(`${LAMBDA_ENDPOINT}/2025-09-09/microvms`, {
          method,
          body: fetchBody,
          signing: { signingDate: FIXED_AMZ_DATE },
        }),
      new RegExp(`Fetch-forbidden method ${method}`)
    );
    assert.equal(fetchCalls, 0);
    await assertHelloStreamReadable(fetchBody);
  }
});

test("signAwsRequest continues to support Fetch-forbidden methods for custom transports", async () => {
  for (const method of ["CONNECT", "TRACE", "TRACK"]) {
    const signed = await lambdaRequest({
      method,
      url: `${LAMBDA_ENDPOINT}/2025-09-09/microvms`,
    });
    assert.equal(signed.method, method);
  }
});

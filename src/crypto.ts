// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { AWS_REQUEST, LOWER_HEX, textEncoder } from "./constants.js";

interface SignatureOptions {
  secretAccessKey: string;
  secretAccessKeyHash?: string | undefined;
  date: string;
  region: string;
  service: string;
  stringToSign: string;
  cache?: Map<string, ArrayBuffer> | undefined;
}

export async function signatureHex(options: SignatureOptions): Promise<string> {
  const secretAccessKeyHash = options.secretAccessKeyHash ?? (await sha256Hex(options.secretAccessKey));
  const cacheKey = ["sigv4", secretAccessKeyHash, options.date, options.region, options.service].join(",");
  let signingKey = options.cache?.get(cacheKey);
  if (!signingKey) {
    const kDate = await hmac(`AWS4${options.secretAccessKey}`, options.date);
    const kRegion = await hmac(kDate, options.region);
    const kService = await hmac(kRegion, options.service);
    signingKey = await hmac(kService, AWS_REQUEST);
    options.cache?.set(cacheKey, signingKey);
  }
  return hex(await hmac(signingKey, options.stringToSign));
}

export async function sha256Hex(value: string | Uint8Array | ArrayBuffer): Promise<string> {
  const bytes = cryptoBufferSource(value);
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

function cryptoBufferSource(value: string | Uint8Array | ArrayBuffer): BufferSource {
  if (typeof value === "string") {
    return textEncoder.encode(value);
  }
  if (value instanceof ArrayBuffer) {
    return value;
  }
  // WebCrypto BufferSource excludes SharedArrayBuffer-backed views in TS DOM types.
  if (ArrayBuffer.isView(value) && value.buffer instanceof ArrayBuffer) {
    return value as Uint8Array<ArrayBuffer>;
  }
  return new Uint8Array(value);
}

async function hmac(key: string | ArrayBuffer, value: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? textEncoder.encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return crypto.subtle.sign("HMAC", cryptoKey, textEncoder.encode(value));
}

function hex(input: ArrayBuffer): string {
  const bytes = new Uint8Array(input);
  let out = "";
  for (const byte of bytes) {
    out += hexNibble(byte >>> 4);
    out += hexNibble(byte & 0x0f);
  }
  return out;
}

function hexNibble(value: number): string {
  return LOWER_HEX.charAt(value);
}

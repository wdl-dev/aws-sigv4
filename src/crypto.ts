// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { AWS_REQUEST, textEncoder } from "./constants.js";
import type { SigningKeyCache } from "./types.js";

const LOWER_HEX = "0123456789abcdef";

interface SignatureOptions {
  secretAccessKey: string;
  secretAccessKeyHash?: string | undefined;
  date: string;
  region: string;
  service: string;
  stringToSign: string;
  cache?: SigningKeyCache | undefined;
}

const inFlightSigningKeys = new WeakMap<SigningKeyCache, Map<string, Promise<ArrayBuffer>>>();

export async function signatureHex(options: SignatureOptions): Promise<string> {
  let signingKey: ArrayBuffer;
  if (options.cache === undefined) {
    signingKey = await deriveSigningKey(options);
  } else {
    const secretAccessKeyHash = options.secretAccessKeyHash ?? (await sha256Hex(options.secretAccessKey));
    const cacheKey = ["sigv4", secretAccessKeyHash, options.date, options.region, options.service].join(",");
    const cachedSigningKey = options.cache.get(cacheKey);
    signingKey = isSigningKeyCacheMiss(cachedSigningKey)
      ? await deriveCachedSigningKey(options, options.cache, cacheKey)
      : cachedSigningKey;
  }
  return hex(await hmac(signingKey, options.stringToSign));
}

function isSigningKeyCacheMiss(value: unknown): value is null | undefined {
  return value === undefined || value === null;
}

async function deriveCachedSigningKey(
  options: SignatureOptions,
  cache: SigningKeyCache,
  cacheKey: string
): Promise<ArrayBuffer> {
  let byKey = inFlightSigningKeys.get(cache);
  if (byKey === undefined) {
    byKey = new Map();
    inFlightSigningKeys.set(cache, byKey);
  }
  const existing = byKey.get(cacheKey);
  if (existing !== undefined) {
    return existing;
  }
  const derivation = (async () => {
    try {
      const signingKey = await deriveSigningKey(options);
      cache.set(cacheKey, signingKey);
      return signingKey;
    } finally {
      byKey.delete(cacheKey);
      if (byKey.size === 0) {
        inFlightSigningKeys.delete(cache);
      }
    }
  })();
  byKey.set(cacheKey, derivation);
  return derivation;
}

async function deriveSigningKey(options: SignatureOptions): Promise<ArrayBuffer> {
  const kDate = await hmac(`AWS4${options.secretAccessKey}`, options.date);
  const kRegion = await hmac(kDate, options.region);
  const kService = await hmac(kRegion, options.service);
  return hmac(kService, AWS_REQUEST);
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

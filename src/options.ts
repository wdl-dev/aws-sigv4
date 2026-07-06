// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { AUTH_PARAM_SEPARATOR_RE, CONTROL_CHAR_RE, WHITESPACE_RE } from "./constants.js";
import { optionalAmzDate } from "./date.js";
import type { SigV4RequestSigningOptions, SigningKeyCache } from "./types.js";
import { rejectNonPrintableAscii } from "./validation.js";

const CLIENT_SIGNING_OPTION_KEYS = new Set([
  "service",
  "region",
  "signingDate",
  "unsignedPayload",
  "signAllHeaders",
  "unsignableHeaders",
  "doubleUrlEncode",
]);
const UNSIGNABLE_HEADER_SNAPSHOTS = new WeakMap<
  object,
  {
    source: Iterable<string>;
    result: { ok: true; value: string[] | undefined } | { ok: false; error: unknown };
  }
>();

export function normalizeClientSigningOptions(options: unknown): SigV4RequestSigningOptions {
  if (options === undefined) {
    return {};
  }
  if (options === null || typeof options !== "object") {
    throw new TypeError("init.signing must be an object");
  }
  for (const key of Object.keys(options)) {
    if (!CLIENT_SIGNING_OPTION_KEYS.has(key)) {
      throw new TypeError(`init.signing.${key} cannot override client credentials or transport options`);
    }
  }
  const record = options as SigV4RequestSigningOptions & Record<string, unknown>;
  const normalized = { ...record };
  const service = optionalCredentialComponent(ownNonNullOption(record, "service"), "init.signing.service");
  setOrDelete(normalized, "service", service);
  const region = optionalCredentialComponent(ownNonNullOption(record, "region"), "init.signing.region");
  setOrDelete(normalized, "region", region);
  const signingDate = optionalAmzDate(ownNonNullOption(record, "signingDate"));
  setOrDelete(normalized, "signingDate", signingDate);
  const unsignedPayload = optionalBoolean(ownOption(record, "unsignedPayload"), "init.signing.unsignedPayload");
  const signAllHeaders = optionalBoolean(ownOption(record, "signAllHeaders"), "init.signing.signAllHeaders");
  const doubleUrlEncode = optionalBoolean(ownOption(record, "doubleUrlEncode"), "init.signing.doubleUrlEncode");
  const unsignableHeaders = snapshotUnsignableHeaders(
    options,
    ownOption(record, "unsignableHeaders"),
    "init.signing.unsignableHeaders"
  );
  setOrDelete(normalized, "unsignedPayload", unsignedPayload);
  setOrDelete(normalized, "signAllHeaders", signAllHeaders);
  setOrDelete(normalized, "unsignableHeaders", unsignableHeaders);
  setOrDelete(normalized, "doubleUrlEncode", doubleUrlEncode);
  return normalized;
}

export function validateCredentialOptions(
  options: unknown,
  message: string
): asserts options is {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string | undefined;
  service: string;
  region: string;
} {
  requireOptionsObject(options, message);
  const record = options as Record<string, unknown>;
  requireCredentialComponent(record.accessKeyId, "accessKeyId");
  requireSecretAccessKey(record.secretAccessKey);
  requireCredentialComponent(record.service, "service");
  requireCredentialComponent(record.region, "region");
  if (record.sessionToken !== undefined) {
    validateSessionToken(record.sessionToken);
  }
}

export function validateSessionToken(value: unknown): asserts value is string {
  requireString(value, "sessionToken");
  rejectControlChars(value, "sessionToken");
  rejectSurroundingWhitespace(value, "sessionToken");
  rejectNonPrintableAscii(value, "sessionToken must contain only printable ASCII characters");
}

export function requireCredentialComponent(value: unknown, name: string): asserts value is string {
  requireString(value, name);
  rejectControlChars(value, name);
  rejectWhitespace(value, name);
  rejectAuthorizationParamSeparators(value, name);
  rejectNonPrintableAscii(value, `${name} must contain only printable ASCII characters`);
  if (value.includes("/")) {
    throw new TypeError(`${name} must not contain /`);
  }
}

export function requireSecretAccessKey(value: unknown): asserts value is string {
  requireString(value, "secretAccessKey");
  rejectControlChars(value, "secretAccessKey");
}

export function requireNonNegativeInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative integer`);
  }
  return value;
}

export function requireNonNegativeFiniteNumber(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative finite number`);
  }
  return value;
}

export function optionalBoolean(value: unknown, name: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new TypeError(`${name} must be a boolean`);
  }
  return value;
}

export function resolveUnsignedPayload(explicit: boolean | undefined, service: string): boolean {
  return explicit ?? service === "s3";
}

export function normalizeUnsignableHeaders(value: unknown, name: string): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] !== "function"
  ) {
    throw new TypeError(`${name} must be an iterable of header names`);
  }
  return [...(value as Iterable<unknown>)].map((header) => {
    if (typeof header !== "string" || header.length === 0) {
      throw new TypeError(`${name} must contain only non-empty strings`);
    }
    return header;
  });
}

export function snapshotUnsignableHeaders(owner: object, source: unknown, name: string): string[] | undefined {
  if (source === undefined) {
    return undefined;
  }
  if (!isIterable(source)) {
    return normalizeUnsignableHeaders(source, name);
  }
  if (!isOneShotIterable(source)) {
    return normalizeUnsignableHeaders(source, name);
  }
  const cached = UNSIGNABLE_HEADER_SNAPSHOTS.get(owner);
  if (cached && cached.source === source) {
    if (cached.result.ok) {
      return cached.result.value;
    }
    throw cached.result.error;
  }
  try {
    const value = normalizeUnsignableHeaders(source, name);
    UNSIGNABLE_HEADER_SNAPSHOTS.set(owner, { source, result: { ok: true, value } });
    return value;
  } catch (error) {
    UNSIGNABLE_HEADER_SNAPSHOTS.set(owner, { source, result: { ok: false, error } });
    throw error;
  }
}

export function requireOptionsObject(value: unknown, message: string): void {
  if (value === null || typeof value !== "object") {
    throw new TypeError(message);
  }
}

export function requireDefinedOption(value: unknown, name: string): void {
  if (value === null || value === undefined) {
    throw new TypeError(`${name} is a required option`);
  }
}

export function requireSigningCache(value: unknown, name: string): SigningKeyCache | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!isSigningCache(value)) {
    throw new TypeError(`${name} must be a Map-like cache`);
  }
  return value;
}

function requireString(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
}

function rejectControlChars(value: string, name: string): void {
  if (CONTROL_CHAR_RE.test(value)) {
    throw new TypeError(`${name} must not contain control characters`);
  }
}

function rejectAuthorizationParamSeparators(value: string, name: string): void {
  if (AUTH_PARAM_SEPARATOR_RE.test(value)) {
    throw new TypeError(`${name} must not contain Authorization parameter separators`);
  }
}

function rejectWhitespace(value: string, name: string): void {
  if (WHITESPACE_RE.test(value)) {
    throw new TypeError(`${name} must not contain whitespace`);
  }
}

function rejectSurroundingWhitespace(value: string, name: string): void {
  if (value.trim() !== value) {
    throw new TypeError(`${name} must not contain leading or trailing whitespace`);
  }
}

function ownNonNullOption(record: Record<string, unknown>, name: string): unknown {
  const value = ownOption(record, name);
  return value === null ? undefined : value;
}

function ownOption(record: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(record, name) ? record[name] : undefined;
}

function optionalCredentialComponent(value: unknown, name: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  requireCredentialComponent(value, name);
  return value;
}

function setOrDelete<K extends keyof SigV4RequestSigningOptions>(
  record: SigV4RequestSigningOptions,
  key: K,
  value: SigV4RequestSigningOptions[K] | undefined
): void {
  if (value === undefined) {
    Reflect.deleteProperty(record, key);
  } else {
    record[key] = value;
  }
}

function isOneShotIterable(value: Iterable<string>): boolean {
  return Object.is(value[Symbol.iterator](), value);
}

function isIterable(value: unknown): value is Iterable<string> {
  return (
    value !== null &&
    typeof value !== "string" &&
    typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === "function"
  );
}

function isSigningCache(value: unknown): value is SigningKeyCache {
  if (value === null || typeof value !== "object" || value instanceof WeakMap) {
    return false;
  }
  const candidate = value as { get?: unknown; set?: unknown };
  return typeof candidate.get === "function" && typeof candidate.set === "function";
}

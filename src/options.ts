// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { optionalAmzDate } from "./date.js";
import type { SigV4RequestSigningOptions, SignAwsRequestOptions, SigningKeyCache } from "./types.js";
import { rejectNonPrintableAscii } from "./validation.js";

const AUTH_PARAM_SEPARATOR_RE = /[,=;]/u;
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/u;
const WHITESPACE_RE = /\s/u;

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
    source: object & Iterable<string>;
    result: { ok: true; value: string[] | undefined } | { ok: false; error: unknown };
  }
>();

export interface NormalizedClientSigningOptions {
  service?: string | undefined;
  region?: string | undefined;
  signingDate?: string | undefined;
  unsignedPayload?: boolean | undefined;
  signAllHeaders?: boolean | undefined;
  unsignableHeaders?: string[] | undefined;
  doubleUrlEncode?: boolean | undefined;
}

export function snapshotSignAwsRequestOptions(value: unknown): SignAwsRequestOptions {
  requireOptionsObject(value, "signAwsRequest options are required");
  const snapshot = { ...(value as SignAwsRequestOptions) };
  validateCredentialOptions(snapshot, "signAwsRequest options are required");
  snapshot.unsignableHeaders = snapshotUnsignableHeaders(
    value as object,
    snapshot.unsignableHeaders,
    "unsignableHeaders"
  );
  return snapshot;
}

export function normalizeClientSigningOptions(options: unknown): NormalizedClientSigningOptions {
  if (options === undefined) {
    return {};
  }
  if (options === null || typeof options !== "object") {
    throw new TypeError("init.signing must be an object");
  }
  const source = { ...(options as SigV4RequestSigningOptions & Record<string, unknown>) };
  for (const key of Object.keys(source)) {
    if (!CLIENT_SIGNING_OPTION_KEYS.has(key)) {
      throw new TypeError(`${signingOptionDisplayName(key)} cannot override client credentials or transport options`);
    }
  }
  return {
    service: optionalCredentialComponent(nullAsUndefined(source.service), "init.signing.service"),
    region: optionalCredentialComponent(nullAsUndefined(source.region), "init.signing.region"),
    signingDate: optionalAmzDate(nullAsUndefined(source.signingDate)),
    unsignedPayload: optionalBoolean(source.unsignedPayload, "init.signing.unsignedPayload"),
    signAllHeaders: optionalBoolean(source.signAllHeaders, "init.signing.signAllHeaders"),
    unsignableHeaders: snapshotUnsignableHeaders(options, source.unsignableHeaders, "init.signing.unsignableHeaders"),
    doubleUrlEncode: optionalBoolean(source.doubleUrlEncode, "init.signing.doubleUrlEncode"),
  };
}

function signingOptionDisplayName(key: string): string {
  if (key.length === 0) {
    return "init.signing option";
  }
  for (let index = 0; index < key.length; index += 1) {
    const codeUnit = key.charCodeAt(index);
    if (codeUnit < 0x20 || codeUnit > 0x7e) {
      return "init.signing option";
    }
  }
  return `init.signing.${key}`;
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
  requireLowercaseCredentialComponent(record.service, "service");
  requireLowercaseCredentialComponent(record.region, "region");
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
  // The secret is HMAC input, not Authorization syntax; compatible services may use valid Unicode.
  if (!value.isWellFormed()) {
    throw new TypeError("secretAccessKey must contain well-formed UTF-16");
  }
}

function requireLowercaseCredentialComponent(value: unknown, name: string): asserts value is string {
  requireCredentialComponent(value, name);
  if (value !== value.toLowerCase()) {
    throw new TypeError(`${name} must be lowercase`);
  }
}

export function requireNonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative integer within the safe integer range`);
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

export function resolveDoubleUrlEncode(explicit: boolean | undefined, service: string): boolean {
  return explicit ?? service !== "s3";
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

function snapshotUnsignableHeaders(owner: object, source: unknown, name: string): string[] | undefined {
  if (source === undefined) {
    return undefined;
  }
  if (!isIterable(source) || !isOneShotIterable(source)) {
    return normalizeUnsignableHeaders(source, name);
  }
  const cached = UNSIGNABLE_HEADER_SNAPSHOTS.get(owner);
  if (cached?.source === source) {
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

function optionalCredentialComponent(value: unknown, name: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  requireLowercaseCredentialComponent(value, name);
  return value;
}

function nullAsUndefined(value: unknown): unknown {
  return value === null ? undefined : value;
}

function isOneShotIterable(value: Iterable<string>): boolean {
  return Object.is(value[Symbol.iterator](), value);
}

function isIterable(value: unknown): value is object & Iterable<string> {
  return (
    value !== null &&
    (typeof value === "object" || typeof value === "function") &&
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

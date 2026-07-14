// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import {
  AMZ_DATE_HEADER,
  AMZ_SECURITY_TOKEN_HEADER,
  AUTHORIZATION_HEADER,
  DEFAULT_UNSIGNABLE_HEADERS,
  HOST_HEADER,
  MANDATORY_SIGNED_HEADERS,
} from "./constants.js";
import { rejectNonPrintableAscii } from "./validation.js";

export interface CanonicalHeaderOptions {
  service: string;
  signAllHeaders?: boolean | undefined;
  unsignableHeaders?: readonly string[] | undefined;
  overwrittenHeaderNames?: readonly string[] | undefined;
}

export interface CanonicalHeaderBlock {
  canonicalHeaders: string;
  signedHeaders: string;
}

export function canonicalHeaderBlock(
  url: URL,
  headers: Headers,
  options: CanonicalHeaderOptions
): CanonicalHeaderBlock {
  const signable = signedHeaderNames(headers, options);
  const canonicalHeaders = signable
    .map((header) => {
      const value = header === HOST_HEADER ? url.host : canonicalHeaderValue(headers.get(header) || "", header);
      return `${header}:${value}`;
    })
    .join("\n");
  return {
    canonicalHeaders,
    signedHeaders: signable.join(";"),
  };
}

export function validateSignedHeaderValues(headers: Headers, options: CanonicalHeaderOptions): void {
  rejectMandatoryHeaderExclusions(headers, options);
  const overwrittenHeaderNames = new Set((options.overwrittenHeaderNames || []).map((value) => value.toLowerCase()));
  for (const header of signedHeaderNames(headers, options)) {
    if (header !== HOST_HEADER && !overwrittenHeaderNames.has(header)) {
      rejectNonPrintableAsciiHeaderValue(headers.get(header) || "", header);
    }
  }
}

export function signerOverwrittenHeaderNames(hasSessionToken: boolean): readonly string[] {
  return hasSessionToken ? [AMZ_DATE_HEADER, AMZ_SECURITY_TOKEN_HEADER] : [AMZ_DATE_HEADER];
}

function signedHeaderNames(headers: Headers, options: CanonicalHeaderOptions): string[] {
  const userUnsignable = new Set((options.unsignableHeaders || []).map((value) => value.toLowerCase()));
  return [...new Set([HOST_HEADER, ...headers.keys()])]
    .filter((header) => header !== AUTHORIZATION_HEADER)
    .filter((header) => {
      if (isMandatorySignedHeader(header, options.service)) {
        return true;
      }
      if (userUnsignable.has(header)) {
        return false;
      }
      return options.signAllHeaders || !DEFAULT_UNSIGNABLE_HEADERS.has(header);
    })
    .sort();
}

function rejectMandatoryHeaderExclusions(headers: Headers, options: CanonicalHeaderOptions): void {
  for (const value of options.unsignableHeaders || []) {
    const header = value.toLowerCase();
    const isPresentDynamicHeader =
      headers.has(header) && (header.startsWith("x-amz-") || (options.service === "s3" && header === "content-md5"));
    if (MANDATORY_SIGNED_HEADERS.has(header) || isPresentDynamicHeader) {
      throw new TypeError(`unsignableHeaders must not include mandatory signed header ${header}`);
    }
  }
}

function isMandatorySignedHeader(header: string, service: string): boolean {
  return (
    MANDATORY_SIGNED_HEADERS.has(header) ||
    header.startsWith("x-amz-") ||
    (service === "s3" && header === "content-md5")
  );
}

function canonicalHeaderValue(value: string, name: string): string {
  rejectNonPrintableAsciiHeaderValue(value, name);
  return value.trim().replace(/\s+/gu, " ");
}

function rejectNonPrintableAsciiHeaderValue(value: string, name: string): void {
  rejectNonPrintableAscii(value, `${name} header value must contain only printable ASCII characters`);
}

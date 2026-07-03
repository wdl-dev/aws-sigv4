// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { RFC3986_EXTRA_ESCAPE_RE } from "./constants.js";

export interface ParsedRequestUrl {
  url: URL;
  href: string;
  pathname: string;
  search: string;
}

export function parseRequestUrl(input: string | URL): ParsedRequestUrl {
  const raw = String(input);
  if (typeof input === "string" && /\s/u.test(raw)) {
    throw new TypeError("url must not contain unescaped whitespace");
  }
  if (typeof input === "string" && raw.includes("\\")) {
    throw new TypeError("url must not contain backslashes");
  }
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new TypeError("url must use http: or https:");
  }
  if (url.username || url.password) {
    throw new TypeError("url must not include username or password");
  }
  if (typeof input !== "string") {
    if (hasMalformedPercentEncoding(url.pathname) || hasMalformedPercentEncoding(url.search)) {
      throw new TypeError("url must not contain malformed percent encoding");
    }
    return {
      url,
      href: stripUrlFragment(url.toString()),
      pathname: url.pathname || "/",
      search: url.search,
    };
  }
  const match = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*([^?#]*)?(\?[^#]*)?/u.exec(raw);
  if (!match) {
    throw new TypeError("url must include scheme://host");
  }
  const pathname = match[1] || "/";
  const search = match[2] || "";
  if (!pathname.isWellFormed() || !search.isWellFormed()) {
    throw new TypeError("url must not contain invalid UTF-16");
  }
  if (hasMalformedPercentEncoding(pathname) || hasMalformedPercentEncoding(search)) {
    throw new TypeError("url must not contain malformed percent encoding");
  }
  return {
    url,
    href: `${url.protocol}//${url.host}${pathname}${search}`,
    pathname,
    search,
  };
}

export function canonicalPathname(pathname: string, service: string, doubleUrlEncode: boolean): string {
  if (!doubleUrlEncode) {
    return canonicalSingleEncodedPathname(pathname);
  }
  if (service !== "s3") {
    if (hasDotPathSegment(pathname)) {
      throw new TypeError("non-S3 doubleUrlEncode URLs must not contain dot path segments");
    }
    return canonicalDoubleEncodedPathname(collapsePathSlashes(pathname));
  }
  return canonicalDoubleEncodedPathname(pathname);
}

export function canonicalQuery(search: string): string {
  if (search === "") {
    return "";
  }
  return search
    .slice(1)
    .split("&")
    .filter((part) => part.length > 0)
    .map((part) => {
      const separator = part.indexOf("=");
      const key = separator === -1 ? part : part.slice(0, separator);
      const value = separator === -1 ? "" : part.slice(separator + 1);
      return [canonicalQueryComponent(key), canonicalQueryComponent(value)] as const;
    })
    .sort(([ak, av], [bk, bv]) => compareCodepoint(ak, bk) || compareCodepoint(av, bv))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

export function hasDotPathSegment(pathname: string): boolean {
  return pathname.split("/").some((segment) => {
    const value = segment.replace(/%2e/giu, ".");
    return value === "." || value === "..";
  });
}

function stripUrlFragment(value: string): string {
  const index = value.indexOf("#");
  return index === -1 ? value : value.slice(0, index);
}

function hasMalformedPercentEncoding(value: string): boolean {
  return /%(?![0-9A-Fa-f]{2})/u.test(value);
}

function canonicalQueryComponent(value: string): string {
  return canonicalUriComponent(value, false);
}

function compareCodepoint(left: string, right: string): -1 | 0 | 1 {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function encodeRfc3986(value: string): string {
  return value.replace(RFC3986_EXTRA_ESCAPE_RE, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalSingleEncodedPathname(pathname: string): string {
  let out = "";
  for (let index = 0; index < pathname.length;) {
    const char = pathname[index];
    if (char === "/") {
      out += "/";
      index += 1;
      continue;
    }
    if (char === "%" && isHexPair(pathname, index + 1)) {
      out += pathname.slice(index, index + 3);
      index += 3;
      continue;
    }
    const codePoint = pathname.codePointAt(index);
    if (codePoint === undefined) {
      break;
    }
    const charValue = String.fromCodePoint(codePoint);
    try {
      out += encodeRfc3986(encodeURIComponent(charValue));
    } catch (err) {
      if (err instanceof URIError) {
        throw new TypeError("url must not contain invalid UTF-16");
      }
      throw err;
    }
    index += charValue.length;
  }
  return out;
}

function canonicalDoubleEncodedPathname(pathname: string): string {
  try {
    return encodeRfc3986(encodeURIComponent(pathname)).replace(/%2F/gu, "/");
  } catch (err) {
    if (err instanceof URIError) {
      throw new TypeError("url must not contain invalid UTF-16");
    }
    throw err;
  }
}

function collapsePathSlashes(pathname: string): string {
  return pathname.replace(/\/+/gu, "/");
}

function canonicalUriComponent(value: string, preserveSlash: boolean): string {
  let out = "";
  for (let index = 0; index < value.length;) {
    const char = value[index];
    if (preserveSlash && char === "/") {
      out += "/";
      index += 1;
      continue;
    }
    if (char === "%" && isHexPair(value, index + 1)) {
      const hex = value.slice(index + 1, index + 3).toUpperCase();
      const byte = parseInt(hex, 16);
      out += isUnreservedByte(byte) ? String.fromCharCode(byte) : `%${hex}`;
      index += 3;
      continue;
    }
    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      break;
    }
    const charValue = String.fromCodePoint(codePoint);
    try {
      out += encodeRfc3986(encodeURIComponent(charValue));
    } catch (err) {
      if (err instanceof URIError) {
        throw new TypeError("url must not contain invalid UTF-16");
      }
      throw err;
    }
    index += charValue.length;
  }
  return out;
}

function isHexPair(value: string, index: number): boolean {
  return /^[0-9A-Fa-f]{2}$/u.test(value.slice(index, index + 2));
}

function isUnreservedByte(byte: number): boolean {
  return (
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    (byte >= 0x30 && byte <= 0x39) ||
    byte === 0x2d ||
    byte === 0x2e ||
    byte === 0x5f ||
    byte === 0x7e
  );
}

// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

export interface SigV4ClientOptions {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string | undefined;
  service: string;
  region: string;
  cache?: SigningKeyCache | undefined;
  retries?: number | undefined;
  initialRetryDelayMs?: number | undefined;
  maxRetryDelayMs?: number | undefined;
  unsignedPayload?: boolean | undefined;
  signAllHeaders?: boolean | undefined;
  unsignableHeaders?: (object & Iterable<string>) | undefined;
  doubleUrlEncode?: boolean | undefined;
  fetch?: ((request: Request) => Promise<Response>) | undefined;
}

export interface SignAwsRequestOptions {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string | undefined;
  service: string;
  region: string;
  method?: string | undefined;
  url: string | URL;
  headers?: HeadersInit | undefined;
  body?: BodyInit | null | undefined;
  signal?: AbortSignal | null | undefined;
  cache?: SigningKeyCache | undefined;
  signingDate?: string | Date | undefined;
  unsignedPayload?: boolean | undefined;
  signAllHeaders?: boolean | undefined;
  unsignableHeaders?: (object & Iterable<string>) | undefined;
  doubleUrlEncode?: boolean | undefined;
}

export interface SigningKeyCache {
  get(key: string): ArrayBuffer | undefined;
  set(key: string, value: ArrayBuffer): unknown;
}

export type SigV4RequestInit = RequestInit & {
  duplex?: "half" | undefined;
  signing?: SigV4RequestSigningOptions | undefined;
};

export interface SigV4RequestSigningOptions {
  service?: string | undefined;
  region?: string | undefined;
  signingDate?: string | Date | undefined;
  unsignedPayload?: boolean | undefined;
  signAllHeaders?: boolean | undefined;
  unsignableHeaders?: (object & Iterable<string>) | undefined;
  doubleUrlEncode?: boolean | undefined;
}

export interface SignedAwsRequest {
  method: string;
  url: string;
  headers: Headers;
  body?: BodyInit | null | undefined;
}

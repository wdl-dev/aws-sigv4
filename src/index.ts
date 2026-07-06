// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

export { SigV4Client } from "./client.js";
export { signAwsRequest } from "./signer.js";
export type {
  SigV4ClientOptions,
  SigV4RequestInit,
  SigV4RequestSigningOptions,
  SignAwsRequestOptions,
  SigningKeyCache,
  SignedAwsRequest,
} from "./types.js";

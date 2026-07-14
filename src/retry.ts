// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === "AbortError";
}

export function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    // Preserve AbortSignal.reason exactly; Web APIs allow non-Error reasons.
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
    return Promise.reject(signal.reason);
  }
  return new Promise((resolve, reject) => {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const onAbort = () => {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
      signal.removeEventListener("abort", onAbort);
      // Preserve AbortSignal.reason exactly; Web APIs allow non-Error reasons.
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
      reject(signal.reason);
    };
    signal.addEventListener("abort", onAbort, { once: true });
    timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
  });
}

export async function cancelResponseBody(response: Response, signal: AbortSignal): Promise<void> {
  let cancellation: Promise<void> | undefined;
  try {
    cancellation = response.body?.cancel();
  } catch {
    // Best-effort connection release before retrying.
    return;
  }
  if (!cancellation) {
    return;
  }
  const settledCancellation = cancellation.catch(() => undefined);
  signal.throwIfAborted();
  const { promise: aborted, reject } = Promise.withResolvers<never>();
  const onAbort = () => {
    // Preserve AbortSignal.reason exactly; Web APIs allow non-Error reasons.
    reject(signal.reason);
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await Promise.race([settledCancellation, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
  signal.throwIfAborted();
}

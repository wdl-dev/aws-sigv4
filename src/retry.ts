// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

export function isAbortError(err: unknown, signal: AbortSignal): boolean {
  return signal.aborted || (err instanceof DOMException && err.name === "AbortError");
}

export function sleep(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) {
    // Preserve AbortSignal.reason exactly; Web APIs allow non-Error reasons.
    // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
    return Promise.reject(abortReason(signal));
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
      reject(abortReason(signal));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
  });
}

export function abortReason(signal: AbortSignal): unknown {
  return signal.reason;
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
  if (signal.aborted) {
    throw abortReason(signal);
  }
  const { promise: aborted, reject } = Promise.withResolvers<never>();
  const onAbort = () => {
    // Preserve AbortSignal.reason exactly; Web APIs allow non-Error reasons.
    reject(abortReason(signal));
  };
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    await Promise.race([settledCancellation, aborted]);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

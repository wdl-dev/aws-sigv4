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

export function cancelResponseBody(response: Response): void {
  try {
    const cancellation = response.body?.cancel();
    if (cancellation) {
      // Start response cleanup without making retry or error progress depend
      // on an underlying source's potentially unbounded cancellation work.
      void cancellation.catch(() => undefined);
    }
  } catch {
    // Response cleanup is best-effort.
  }
}

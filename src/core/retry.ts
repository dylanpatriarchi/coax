/**
 * Retry policy for TRANSIENT target failures.
 *
 * WHY: a real scan is hundreds of round-trips against someone's staging agent.
 * Losing an eight-minute run — and its report — because one request hit a 429 or
 * a gateway timeout makes COAX useless as a CI gate, which is exactly the job it
 * is for. So a bounded, opt-in retry sits around the target call.
 *
 * Design decisions:
 *   - Only TRANSIENT failures retry. A 400, a 401, or a bug in an adapter is a
 *     real answer and must surface immediately; silently re-sending a payload
 *     that the target rejected would inflate the attempt count and hide the
 *     defect. `isTransientError` is deliberately conservative.
 *   - Backoff is exponential and JITTER-FREE: library code may not call
 *     `Math.random()`, and a reproducible scan may not depend on wall-clock
 *     noise. Delay for attempt n is `baseMs * 2^(n-1)`.
 *   - `sleep` is injectable so tests exercise the backoff without waiting.
 */
import { LlmHttpError, LlmTimeoutError, isAbort } from '../llm/http-error.js';

/** Node/undici network hiccups that are worth one more shot. */
const TRANSIENT_CODES = [
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'ENOTFOUND',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
];

const TRANSIENT_TEXT =
  /\b(timed? ?out|timeout|socket hang up|network error|fetch failed|temporarily unavailable|rate ?limit(ed)?|too many requests|service unavailable|bad gateway|gateway timeout)\b/i;

/** HTTP statuses that mean "try again", not "you asked for the wrong thing". */
export function isTransientStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

/** True when a caught error is worth retrying. Conservative by design. */
export function isTransientError(err: unknown): boolean {
  if (isAbort(err)) return true;
  if (err instanceof LlmTimeoutError) return true;
  if (err instanceof LlmHttpError) return isTransientStatus(err.status);

  if (typeof err === 'object' && err !== null) {
    const e = err as { code?: unknown; status?: unknown; statusCode?: unknown; message?: unknown };
    if (typeof e.code === 'string' && TRANSIENT_CODES.includes(e.code)) return true;
    const status = typeof e.status === 'number' ? e.status : e.statusCode;
    if (typeof status === 'number' && isTransientStatus(status)) return true;
    if (typeof e.message === 'string' && TRANSIENT_TEXT.test(e.message)) return true;
    // undici wraps the real reason in `cause`.
    if ('cause' in err && err.cause !== err)
      return isTransientError((err as { cause: unknown }).cause);
  }
  return false;
}

export interface RetryOptions {
  /** Extra attempts after the first. 0 (the default) disables retrying. */
  retries?: number;
  /** First backoff delay in ms; doubles each attempt. */
  backoffMs?: number;
  /** Injectable for tests — real code gets `setTimeout`. */
  sleep?: (ms: number) => Promise<void>;
  /** Called before each retry so the CLI can report the flake. */
  onRetry?: (info: { attempt: number; delayMs: number; error: unknown }) => void;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/** Deterministic exponential backoff: `baseMs * 2^(attempt-1)`. */
export function backoffFor(attempt: number, baseMs: number): number {
  return baseMs * 2 ** (attempt - 1);
}

/** Run `fn`, retrying only transient failures, with bounded exponential backoff. */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions = {}): Promise<T> {
  const retries = opts.retries ?? 0;
  const baseMs = opts.backoffMs ?? 250;
  const sleep = opts.sleep ?? defaultSleep;

  let lastError: unknown;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt === retries || !isTransientError(err)) throw err;
      const delayMs = backoffFor(attempt + 1, baseMs);
      opts.onRetry?.({ attempt: attempt + 1, delayMs, error: err });
      await sleep(delayMs);
    }
  }
  throw lastError;
}

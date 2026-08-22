import { describe, expect, it } from 'vitest';
import { LlmHttpError, LlmTimeoutError } from '../llm/http-error.js';
import { backoffFor, isTransientError, isTransientStatus, withRetry } from './retry.js';

/** A sleep that records the delays instead of taking them. */
function fakeSleep(): { sleep: (ms: number) => Promise<void>; delays: number[] } {
  const delays: number[] = [];
  return {
    delays,
    sleep: async (ms) => {
      delays.push(ms);
    },
  };
}

describe('isTransientError', () => {
  it('accepts rate limits, timeouts and 5xx', () => {
    expect(isTransientError(new LlmHttpError('429', 429, 'openai'))).toBe(true);
    expect(isTransientError(new LlmHttpError('503', 503, 'openai'))).toBe(true);
    expect(isTransientError(new LlmTimeoutError('openai', 1000))).toBe(true);
    expect(isTransientError(Object.assign(new Error('abort'), { name: 'AbortError' }))).toBe(true);
    expect(isTransientError(Object.assign(new Error('boom'), { code: 'ECONNRESET' }))).toBe(true);
    expect(isTransientError(new Error('socket hang up'))).toBe(true);
    expect(isTransientError({ status: 502 })).toBe(true);
  });

  it('rejects real answers, which must surface immediately', () => {
    expect(isTransientError(new LlmHttpError('401', 401, 'openai'))).toBe(false);
    expect(isTransientError(new LlmHttpError('400', 400, 'openai'))).toBe(false);
    expect(isTransientError(new Error('adapter returned no output'))).toBe(false);
    expect(isTransientError(undefined)).toBe(false);
  });

  it('unwraps the undici `cause` chain', () => {
    const err = Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('inner'), { code: 'ETIMEDOUT' }),
    });
    expect(isTransientError(err)).toBe(true);
  });

  it('classifies statuses the way an operator would', () => {
    expect([408, 429, 500, 503].every(isTransientStatus)).toBe(true);
    expect([200, 400, 401, 404].some(isTransientStatus)).toBe(false);
  });
});

describe('withRetry', () => {
  it('returns the first success without sleeping', async () => {
    const { sleep, delays } = fakeSleep();
    let calls = 0;
    const value = await withRetry(
      async () => {
        calls += 1;
        return 'ok';
      },
      { retries: 3, sleep },
    );
    expect(value).toBe('ok');
    expect(calls).toBe(1);
    expect(delays).toEqual([]);
  });

  it('retries a transient failure with deterministic exponential backoff', async () => {
    const { sleep, delays } = fakeSleep();
    let calls = 0;
    const value = await withRetry(
      async () => {
        calls += 1;
        if (calls < 3) throw new LlmHttpError('429', 429, 'openai');
        return calls;
      },
      { retries: 3, backoffMs: 100, sleep },
    );
    expect(value).toBe(3);
    expect(delays).toEqual([100, 200]);
  });

  it('does not retry a non-transient failure', async () => {
    const { sleep, delays } = fakeSleep();
    let calls = 0;
    await expect(
      withRetry(
        async () => {
          calls += 1;
          throw new LlmHttpError('401', 401, 'openai');
        },
        { retries: 5, sleep },
      ),
    ).rejects.toThrow('401');
    expect(calls).toBe(1);
    expect(delays).toEqual([]);
  });

  it('gives up after the budget and rethrows the last error', async () => {
    const { sleep, delays } = fakeSleep();
    const seen: number[] = [];
    await expect(
      withRetry(
        async () => {
          throw new LlmTimeoutError('openai', 10);
        },
        { retries: 2, backoffMs: 50, sleep, onRetry: ({ attempt }) => seen.push(attempt) },
      ),
    ).rejects.toBeInstanceOf(LlmTimeoutError);
    expect(delays).toEqual([50, 100]);
    expect(seen).toEqual([1, 2]);
  });

  it('never retries when retries is 0 (the default)', async () => {
    let calls = 0;
    await expect(
      withRetry(async () => {
        calls += 1;
        throw new LlmTimeoutError('openai', 10);
      }),
    ).rejects.toBeInstanceOf(LlmTimeoutError);
    expect(calls).toBe(1);
  });

  it('doubles with no jitter, so a run is reproducible', () => {
    expect([1, 2, 3, 4].map((n) => backoffFor(n, 250))).toEqual([250, 500, 1000, 2000]);
  });
});

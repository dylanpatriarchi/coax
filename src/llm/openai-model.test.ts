import { describe, expect, it } from 'vitest';
import { openAIModel } from './openai-model.js';
import { LlmHttpError, LlmTimeoutError } from './http-error.js';

interface Seen {
  url: string;
  body: any;
  headers: Record<string, string>;
}

function fakeFetch(json: unknown, capture?: (seen: Seen) => void): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    capture?.({
      url: String(url),
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      headers: (init?.headers ?? {}) as Record<string, string>,
    });
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as unknown as typeof fetch;
}

function failingFetch(status: number, body = 'nope'): typeof fetch {
  return (async () => new Response(body, { status })) as unknown as typeof fetch;
}

const reply = (content: string | null) => ({ choices: [{ message: { content } }] });

describe('openAIModel', () => {
  it('posts a single user message to /chat/completions and returns the content', async () => {
    let seen: Seen | undefined;
    const model = openAIModel({
      model: 'gpt-test',
      baseUrl: 'http://localhost:1234/v1/',
      apiKey: 'sk-secret',
      fetchImpl: fakeFetch(reply('judged'), (s) => (seen = s)),
    });
    expect(model.id).toBe('openai:gpt-test');
    expect(await model.complete('rate this')).toBe('judged');
    expect(seen?.url).toBe('http://localhost:1234/v1/chat/completions');
    expect(seen?.body.model).toBe('gpt-test');
    expect(seen?.body.messages).toEqual([{ role: 'user', content: 'rate this' }]);
    expect(seen?.headers.authorization).toBe('Bearer sk-secret');
  });

  it('omits sampling parameters unless configured', async () => {
    let seen: Seen | undefined;
    const model = openAIModel({ fetchImpl: fakeFetch(reply('ok'), (s) => (seen = s)) });
    await model.complete('x');
    expect(seen?.body.temperature).toBeUndefined();
    expect(seen?.body.seed).toBeUndefined();
    expect(seen?.body.max_tokens).toBeUndefined();

    const tuned = openAIModel({
      temperature: 0,
      seed: 42,
      maxTokens: 64,
      fetchImpl: fakeFetch(reply('ok'), (s) => (seen = s)),
    });
    await tuned.complete('x');
    expect(seen?.body).toMatchObject({ temperature: 0, seed: 42, max_tokens: 64 });
  });

  it('sends no authorization header when no key is configured (local endpoints)', async () => {
    let seen: Seen | undefined;
    const model = openAIModel({
      baseUrl: 'http://localhost:8000/v1',
      fetchImpl: fakeFetch(reply('ok'), (s) => (seen = s)),
    });
    await model.complete('x');
    expect(seen?.headers.authorization).toBeUndefined();
  });

  it('treats a null content as an empty completion', async () => {
    const model = openAIModel({ fetchImpl: fakeFetch(reply(null)) });
    expect(await model.complete('x')).toBe('');
  });

  it('rejects a malformed response rather than scoring it as empty', async () => {
    const model = openAIModel({ fetchImpl: fakeFetch({ oops: true }) });
    await expect(model.complete('x')).rejects.toThrow();
  });

  it.each([
    [401, /authentication rejected; check OPENAI_API_KEY/],
    [429, /rate limited/],
    [500, /provider-side failure/],
  ])('maps HTTP %i to an actionable error', async (status, expected) => {
    const model = openAIModel({ apiKey: 'sk-secret', fetchImpl: failingFetch(status) });
    const err = await model.complete('x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LlmHttpError);
    expect((err as LlmHttpError).status).toBe(status);
    expect((err as Error).message).toMatch(expected);
    // The key must never leak into an error surface.
    expect((err as Error).message).not.toContain('sk-secret');
  });

  it('aborts on timeout with a clear error', async () => {
    const hanging = ((_url: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          const err = new Error('aborted');
          err.name = 'AbortError';
          reject(err);
        });
      })) as unknown as typeof fetch;
    const model = openAIModel({ timeoutMs: 5, fetchImpl: hanging });
    await expect(model.complete('x')).rejects.toThrow(LlmTimeoutError);
  });

  it('estimates a non-zero cost so the USD budget can bite', () => {
    const model = openAIModel({ model: 'gpt-4o' });
    expect(model.estimateUsd?.('a'.repeat(4000), 'b'.repeat(400))).toBeGreaterThan(0);
  });
});

import { describe, expect, it } from 'vitest';
import { anthropicModel, ANTHROPIC_VERSION, DEFAULT_ANTHROPIC_MODEL } from './anthropic-model.js';
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

const message = (blocks: unknown[], stopReason = 'end_turn') => ({
  id: 'msg_1',
  type: 'message',
  role: 'assistant',
  content: blocks,
  stop_reason: stopReason,
  usage: { input_tokens: 10, output_tokens: 5 },
});

describe('anthropicModel', () => {
  it('posts to /v1/messages with the API-key and version headers', async () => {
    let seen: Seen | undefined;
    const model = anthropicModel({
      apiKey: 'sk-ant-secret',
      fetchImpl: fakeFetch(message([{ type: 'text', text: 'clean' }]), (s) => (seen = s)),
    });
    expect(model.id).toBe(`anthropic:${DEFAULT_ANTHROPIC_MODEL}`);
    expect(await model.complete('judge this')).toBe('clean');
    expect(seen?.url).toBe('https://api.anthropic.com/v1/messages');
    expect(seen?.headers['x-api-key']).toBe('sk-ant-secret');
    expect(seen?.headers['anthropic-version']).toBe(ANTHROPIC_VERSION);
    expect(seen?.headers.authorization).toBeUndefined();
    expect(seen?.body.messages).toEqual([{ role: 'user', content: 'judge this' }]);
  });

  it('always sends max_tokens and omits sampling parameters by default', async () => {
    let seen: Seen | undefined;
    const model = anthropicModel({
      apiKey: 'k',
      fetchImpl: fakeFetch(message([{ type: 'text', text: 'ok' }]), (s) => (seen = s)),
    });
    await model.complete('x');
    expect(seen?.body.max_tokens).toBeGreaterThan(0);
    expect(seen?.body.temperature).toBeUndefined();
    expect(seen?.body.system).toBeUndefined();
  });

  it('sends a system prompt and an explicit temperature when configured', async () => {
    let seen: Seen | undefined;
    const model = anthropicModel({
      apiKey: 'k',
      model: 'claude-sonnet-5',
      system: 'You are a strict evaluator.',
      temperature: 0,
      maxTokens: 256,
      fetchImpl: fakeFetch(message([{ type: 'text', text: 'ok' }]), (s) => (seen = s)),
    });
    await model.complete('x');
    expect(seen?.body).toMatchObject({
      model: 'claude-sonnet-5',
      max_tokens: 256,
      system: 'You are a strict evaluator.',
      temperature: 0,
    });
  });

  it('joins text blocks and ignores thinking blocks', async () => {
    const model = anthropicModel({
      apiKey: 'k',
      fetchImpl: fakeFetch(
        message([
          { type: 'thinking', thinking: '' },
          { type: 'text', text: '{"violation": true,' },
          { type: 'text', text: ' "reason": "x"}' },
        ]),
      ),
    });
    expect(await model.complete('x')).toBe('{"violation": true, "reason": "x"}');
  });

  it('surfaces a refusal as an error so callers keep their deterministic verdict', async () => {
    const model = anthropicModel({
      apiKey: 'k',
      fetchImpl: fakeFetch(message([], 'refusal')),
    });
    await expect(model.complete('x')).rejects.toThrow(/refusal/);
  });

  it.each([
    [401, /authentication rejected; check ANTHROPIC_API_KEY/],
    [429, /rate limited/],
    [529, /provider-side failure/],
  ])('maps HTTP %i to an actionable error', async (status, expected) => {
    const model = anthropicModel({
      apiKey: 'sk-ant-secret',
      fetchImpl: (async () => new Response('boom', { status })) as unknown as typeof fetch,
    });
    const err = await model.complete('x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LlmHttpError);
    expect((err as Error).message).toMatch(expected);
    expect((err as Error).message).not.toContain('sk-ant-secret');
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
    const model = anthropicModel({ apiKey: 'k', timeoutMs: 5, fetchImpl: hanging });
    await expect(model.complete('x')).rejects.toThrow(LlmTimeoutError);
  });
});

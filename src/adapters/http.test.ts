import { describe, expect, it } from 'vitest';
import { HttpAgent } from './http.js';
import { supportsInjection, supportsTools } from '../core/target.js';

/** Build a fake fetch that captures the last request and returns a fixed JSON. */
function fakeFetch(json: unknown, capture?: (url: string, body: unknown) => void): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    capture?.(String(url), init?.body ? JSON.parse(String(init.body)) : undefined);
    return new Response(JSON.stringify(json), { status: 200, headers: { 'content-type': 'application/json' } });
  }) as unknown as typeof fetch;
}

describe('HttpAgent', () => {
  it('sends the message and parses a default {output,toolCalls} response', async () => {
    let seen: { url: string; body: unknown } | undefined;
    const agent = new HttpAgent({
      url: 'http://localhost:9999/chat',
      fetchImpl: fakeFetch({ output: 'hi there', toolCalls: [] }, (url, body) => {
        seen = { url, body };
      }),
    });
    const res = await agent.sendMessage({ message: 'hello' });
    expect(res.output).toBe('hi there');
    expect(seen?.url).toBe('http://localhost:9999/chat');
    expect((seen?.body as { message: string }).message).toBe('hello');
  });

  it('feature-detects injection and tools', () => {
    const agent = new HttpAgent({ url: 'http://x', tools: [{ name: 't', description: '', parameters: {}, forbidden: true }] });
    expect(supportsInjection(agent)).toBe(true);
    expect(supportsTools(agent)).toBe(true);
  });

  it('includes staged indirect content in the request body', async () => {
    let body: unknown;
    const agent = new HttpAgent({
      url: 'http://x',
      fetchImpl: fakeFetch({ output: 'ok' }, (_u, b) => {
        body = b;
      }),
    });
    await agent.injectContent({ channel: 'web', source: 'https://e.x', content: 'PWN' });
    await agent.sendMessage({ message: 'summarize' });
    const ingested = (body as { ingested: { content: string }[] }).ingested;
    expect(ingested).toHaveLength(1);
    expect(ingested[0]!.content).toBe('PWN');
  });

  it('honors a custom buildBody / parseResponse', async () => {
    const agent = new HttpAgent({
      url: 'http://x',
      buildBody: (input) => ({ q: input.message }),
      parseResponse: (json) => ({ output: (json as { answer: string }).answer, toolCalls: [] }),
      fetchImpl: fakeFetch({ answer: 'custom' }),
    });
    const res = await agent.sendMessage({ message: 'x' });
    expect(res.output).toBe('custom');
  });

  it('reset clears staged content', async () => {
    let body: unknown;
    const agent = new HttpAgent({ url: 'http://x', fetchImpl: fakeFetch({ output: 'ok' }, (_u, b) => (body = b)) });
    await agent.injectContent({ channel: 'email', source: 's', content: 'x' });
    await agent.reset();
    await agent.sendMessage({ message: 'm' });
    expect((body as { ingested: unknown[] }).ingested).toHaveLength(0);
  });

  it('throws on a non-2xx response', async () => {
    const agent = new HttpAgent({
      url: 'http://x',
      fetchImpl: (async () => new Response('boom', { status: 500 })) as unknown as typeof fetch,
    });
    await expect(agent.sendMessage({ message: 'm' })).rejects.toThrow(/HTTP 500/);
  });
});

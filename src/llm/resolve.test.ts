import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  defaultJudgeModel,
  providerForModel,
  readLlmEnv,
  resetDefaultJudgeModel,
  resolveJudgeModel,
  resolveModel,
  selectProvider,
} from './resolve.js';
import { BudgetExceededError } from './model.js';

/** Stub the global fetch so a resolved client can be driven without a network. */
function stubFetch(body: unknown): ReturnType<typeof vi.fn> {
  const fn = vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

const chatReply = { choices: [{ message: { content: 'ok' } }] };

afterEach(() => {
  vi.unstubAllGlobals();
  resetDefaultJudgeModel();
});

describe('readLlmEnv', () => {
  it('treats blank values as unset (a .env copied from .env.example)', () => {
    const cfg = readLlmEnv({ OPENAI_API_KEY: '', ANTHROPIC_API_KEY: '   ', COAX_MODEL: '' });
    expect(cfg.OPENAI_API_KEY).toBeUndefined();
    expect(cfg.ANTHROPIC_API_KEY).toBeUndefined();
    expect(cfg.COAX_MODEL).toBeUndefined();
  });

  it('fails loudly on a malformed USD ceiling', () => {
    expect(() => readLlmEnv({ COAX_MAX_USD: 'abc' })).toThrow(/COAX_MAX_USD/);
  });

  it('fails loudly on a non-positive call cap and an unknown provider', () => {
    expect(() => readLlmEnv({ COAX_MAX_LLM_CALLS: '0' })).toThrow(/COAX_MAX_LLM_CALLS/);
    expect(() => readLlmEnv({ COAX_PROVIDER: 'gemini' })).toThrow(/COAX_PROVIDER/);
  });

  it('reads the offline flag in every truthy spelling', () => {
    for (const v of ['1', 'true', 'YES', 'on']) {
      expect(readLlmEnv({ COAX_OFFLINE: v }).offline).toBe(true);
    }
    expect(readLlmEnv({ COAX_OFFLINE: 'false' }).offline).toBe(false);
    expect(readLlmEnv({}).offline).toBe(false);
  });
});

describe('provider selection', () => {
  it.each([
    ['claude-opus-5', 'anthropic'],
    ['gpt-4o-mini', 'openai'],
    ['o3-mini', 'openai'],
    ['qwen3.5:0.8b', 'ollama'],
  ])('infers %s as %s', (model, provider) => {
    expect(providerForModel(model)).toBe(provider);
  });

  it('prefers an explicit COAX_PROVIDER over the model id and keys', () => {
    const cfg = readLlmEnv({
      COAX_PROVIDER: 'ollama',
      COAX_MODEL: 'claude-opus-5',
      ANTHROPIC_API_KEY: 'k',
    });
    expect(selectProvider(cfg)).toBe('ollama');
  });

  it('falls back to whichever key is present, then to local Ollama', () => {
    expect(selectProvider(readLlmEnv({ ANTHROPIC_API_KEY: 'k' }))).toBe('anthropic');
    expect(selectProvider(readLlmEnv({ OPENAI_API_KEY: 'k' }))).toBe('openai');
    expect(selectProvider(readLlmEnv({}))).toBe('ollama');
  });
});

describe('resolveModel', () => {
  it('builds an Anthropic client from ANTHROPIC_API_KEY', () => {
    expect(resolveModel({ ANTHROPIC_API_KEY: 'k' })?.id).toBe('cached:anthropic:claude-opus-5');
    expect(resolveModel({ ANTHROPIC_API_KEY: 'k', COAX_MODEL: 'claude-sonnet-5' })?.id).toBe(
      'cached:anthropic:claude-sonnet-5',
    );
  });

  it('builds an OpenAI client from OPENAI_API_KEY', () => {
    expect(resolveModel({ OPENAI_API_KEY: 'k' })?.id).toBe('cached:openai:gpt-4o-mini');
    expect(resolveModel({ OPENAI_API_KEY: 'k', COAX_MODEL: 'gpt-4o' })?.id).toBe(
      'cached:openai:gpt-4o',
    );
  });

  it('falls back to local Ollama when nothing is configured', () => {
    expect(resolveModel({})?.id).toBe('cached:ollama:qwen3.5:0.8b');
    expect(resolveModel({ COAX_MODEL: 'llama3:8b' })?.id).toBe('cached:ollama:llama3:8b');
  });

  it('allows a keyless OpenAI-compatible endpoint (vLLM / llama.cpp)', () => {
    expect(
      resolveModel({ COAX_PROVIDER: 'openai', OPENAI_BASE_URL: 'http://localhost:8000/v1' })?.id,
    ).toBe('cached:openai:gpt-4o-mini');
  });

  it('fails loudly when the selected provider has no key', () => {
    expect(() => resolveModel({ COAX_PROVIDER: 'openai' })).toThrow(/OPENAI_API_KEY/);
    expect(() => resolveModel({ COAX_MODEL: 'claude-opus-5' })).toThrow(/ANTHROPIC_API_KEY/);
  });

  it('returns null for COAX_PROVIDER=none', () => {
    expect(resolveModel({ COAX_PROVIDER: 'none', ANTHROPIC_API_KEY: 'k' })).toBeNull();
  });

  it('enforces COAX_MAX_LLM_CALLS through the returned model', async () => {
    const fetchMock = stubFetch(chatReply);
    const model = resolveModel({ OPENAI_API_KEY: 'k', COAX_MAX_LLM_CALLS: '1' })!;
    expect(await model.complete('first')).toBe('ok');
    await expect(model.complete('second')).rejects.toThrow(BudgetExceededError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('enforces COAX_MAX_USD through the returned model', async () => {
    stubFetch(chatReply);
    const model = resolveModel({
      OPENAI_API_KEY: 'k',
      COAX_MODEL: 'gpt-4o',
      COAX_MAX_USD: '0.000001',
    })!;
    await model.complete('a'.repeat(4000));
    await expect(model.complete('b'.repeat(4000))).rejects.toThrow(/USD budget/);
  });
});

describe('COAX_OFFLINE kill switch', () => {
  it('returns null and never constructs a network client', () => {
    const fetchMock = stubFetch(chatReply);
    for (const env of [
      { COAX_OFFLINE: '1', ANTHROPIC_API_KEY: 'k' },
      { COAX_OFFLINE: 'true', OPENAI_API_KEY: 'k', COAX_MODEL: 'gpt-4o' },
      { COAX_OFFLINE: '1', COAX_PROVIDER: 'ollama' },
    ]) {
      expect(resolveModel(env)).toBeNull();
      expect(resolveJudgeModel(env)).toBeNull();
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('still refuses when the offline flag is combined with a malformed budget', () => {
    expect(() => resolveModel({ COAX_OFFLINE: '1', COAX_MAX_USD: 'abc' })).toThrow(/COAX_MAX_USD/);
  });
});

describe('resolveJudgeModel', () => {
  it('is null unless the environment explicitly configures a model', () => {
    expect(resolveJudgeModel({})).toBeNull();
    expect(resolveJudgeModel({ COAX_MAX_USD: '1' })).toBeNull();
    expect(resolveJudgeModel({ ANTHROPIC_API_KEY: 'k' })?.id).toBe(
      'cached:anthropic:claude-opus-5',
    );
    expect(resolveJudgeModel({ COAX_PROVIDER: 'ollama' })?.id).toBe('cached:ollama:qwen3.5:0.8b');
  });

  it('memoises the shared judge until it is reset', () => {
    const first = defaultJudgeModel({ ANTHROPIC_API_KEY: 'k' });
    expect(defaultJudgeModel({})).toBe(first);
    resetDefaultJudgeModel();
    expect(defaultJudgeModel({})).toBeNull();
  });
});

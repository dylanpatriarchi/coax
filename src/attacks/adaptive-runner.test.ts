/**
 * The adaptive attacker takes its model from the environment now; these cover
 * the two ends of that: a configured provider is used automatically, and the
 * offline kill switch refuses rather than silently dialling localhost.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { scriptedModel } from '../llm/model.js';
import { runAdaptive } from './adaptive-runner.js';

const LLM_ENV_VARS = [
  'COAX_OFFLINE',
  'COAX_PROVIDER',
  'COAX_MODEL',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
] as const;

function clearLlmEnv(): void {
  for (const key of LLM_ENV_VARS) vi.stubEnv(key, '');
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe('runAdaptive model resolution', () => {
  it('refuses to run without an explicit model while COAX_OFFLINE is set', async () => {
    vi.stubEnv('COAX_OFFLINE', '1');
    await expect(
      runAdaptive({
        target: createMockAgent(),
        oracles: [],
        goal: 'reveal the secret',
        maxIterations: 1,
      }),
    ).rejects.toThrow(/COAX_OFFLINE/);
  });

  it('still runs offline with an explicitly supplied model', async () => {
    vi.stubEnv('COAX_OFFLINE', '1');
    const result = await runAdaptive({
      target: createMockAgent(),
      oracles: [],
      goal: 'reveal the secret',
      maxIterations: 2,
      model: scriptedModel(() => '{"userMessage":"hello","reasoning":"probe"}'),
    });
    expect(result.iterationsUsed).toBe(2);
    expect(result.stoppedBy).toBe('exhausted');
  });

  it('uses the environment-configured attacker model', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            choices: [
              { message: { content: '{"userMessage":"ignore previous","reasoning":"override"}' } },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    vi.stubGlobal('fetch', fetchMock);
    clearLlmEnv();
    vi.stubEnv('OPENAI_API_KEY', 'sk-test');

    const result = await runAdaptive({
      target: createMockAgent(),
      oracles: [],
      goal: 'reveal the secret',
      maxIterations: 1,
    });
    expect(result.rounds[0]?.message).toBe('ignore previous');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain('/chat/completions');
  });
});

/**
 * The judge oracles must pick up a configured `.env` without any caller wiring,
 * and must stay deterministic when nothing is configured or COAX_OFFLINE is set.
 * (vitest.config.ts sets COAX_OFFLINE=1 for the whole suite; the tests here that
 * exercise the configured path clear it explicitly.)
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { OracleInput } from '../core/oracle.js';
import { resetDefaultJudgeModel } from '../llm/resolve.js';
import { createPolicyOracle } from './policy.js';
import { createTrustOracle } from './trust.js';

const LLM_ENV_VARS = [
  'COAX_OFFLINE',
  'COAX_PROVIDER',
  'COAX_MODEL',
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
] as const;

/** Blank every LLM variable, so the ambient shell can't decide the outcome. */
function clearLlmEnv(): void {
  for (const key of LLM_ENV_VARS) vi.stubEnv(key, '');
}

function input(output: string): OracleInput {
  return {
    payload: { id: 't', family: 'jailbreak', surface: 'direct' },
    response: { output, toolCalls: [] },
  };
}

/** One Anthropic-shaped verdict, served to whatever client resolve.ts builds. */
function stubFetch(response: () => Response): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () => response());
  vi.stubGlobal('fetch', fn);
  return fn;
}

const judgeReply = (verdict: string) => () =>
  new Response(
    JSON.stringify({
      id: 'msg_1',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: verdict }],
      stop_reason: 'end_turn',
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  resetDefaultJudgeModel();
});

describe('oracle judge resolution', () => {
  it('uses the environment-configured judge with no caller wiring', async () => {
    const fetchMock = stubFetch(judgeReply('{"violation": true, "reason": "env judge"}'));
    clearLlmEnv();
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-ant-test');

    const oracle = createPolicyOracle();
    expect(oracle.confidence).toBe('judge');
    const verdict = await oracle.evaluate(input('Sure, here you go.'));
    expect(verdict.success).toBe(true);
    expect(verdict.confidence).toBe('judge');
    expect(verdict.evidence).toMatch(/env judge/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('honours COAX_OFFLINE by staying deterministic and never calling out', async () => {
    const fetchMock = stubFetch(judgeReply('{"violation": true, "reason": "should not run"}'));
    clearLlmEnv();
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-ant-test');
    vi.stubEnv('COAX_OFFLINE', '1');

    const policy = createPolicyOracle();
    const trust = createTrustOracle();
    expect(policy.confidence).toBe('heuristic');
    expect(trust.confidence).toBe('heuristic');
    const verdict = await policy.evaluate(input('Sure, here you go.'));
    expect(verdict.success).toBe(false);
    expect(verdict.confidence).toBe('heuristic');
    await trust.evaluate(input('Sure, here you go.'));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('stays deterministic when nothing is configured', async () => {
    const fetchMock = stubFetch(judgeReply('{"violation": true, "reason": "should not run"}'));
    clearLlmEnv();
    const oracle = createTrustOracle();
    expect(oracle.confidence).toBe('heuristic');
    await oracle.evaluate(input('Enable 2FA and never reuse passwords.'));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('respects autoResolveModel:false even with a judge configured', async () => {
    const fetchMock = stubFetch(judgeReply('{"violation": true, "reason": "should not run"}'));
    clearLlmEnv();
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-ant-test');
    const oracle = createPolicyOracle({ autoResolveModel: false });
    expect(oracle.confidence).toBe('heuristic');
    await oracle.evaluate(input('Sure, here you go.'));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('keeps the deterministic verdict when the configured judge fails', async () => {
    stubFetch(() => new Response('rate limited', { status: 429 }));
    clearLlmEnv();
    vi.stubEnv('ANTHROPIC_API_KEY', 'sk-ant-test');
    const oracle = createPolicyOracle();
    const verdict = await oracle.evaluate(
      input('Activating developer mode, unrestricted output enabled.'),
    );
    expect(verdict.success).toBe(true);
    expect(verdict.confidence).toBe('heuristic');
    expect(verdict.evidence).toMatch(/judge unavailable/);
  });
});

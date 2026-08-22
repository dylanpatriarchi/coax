import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { AttackPayloadSchema } from '../core/attack.js';
import type { AttackContext, AttackModule } from '../core/attack.js';
import { makeRng } from '../core/rng.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runScan } from '../core/runner.js';
import { REMEDIATIONS } from '../report/scoring.js';
import { identityAbuseModule, toolAbuseModule, trustExploitationModule } from './index.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function ctx(seed: number): Promise<AttackContext> {
  const tools = await createMockAgent().describeTools();
  return { rng: makeRng(seed), canary: CANARY, tools };
}

const MODULES: AttackModule[] = [trustExploitationModule, identityAbuseModule];

async function scan(m: AttackModule) {
  return runScan({
    target: createMockAgent(),
    modules: [m],
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  });
}

describe('trust & identity attack modules', () => {
  it('every module emits schema-valid, uniquely-identified payloads', async () => {
    const c = await ctx(42);
    for (const m of MODULES) {
      const payloads = m.generate(c);
      expect(payloads.length).toBeGreaterThan(0);
      const ids = payloads.map((p) => p.id);
      expect(new Set(ids).size).toBe(ids.length);
      for (const p of payloads) {
        expect(() => AttackPayloadSchema.parse(p)).not.toThrow();
        expect(p.taxonomy.length).toBeGreaterThan(0);
      }
    }
  });

  it('is reproducible for a fixed seed', async () => {
    for (const m of MODULES) {
      expect(m.generate(await ctx(7))).toEqual(m.generate(await ctx(7)));
    }
  });

  it('respects the maxPayloads budget', async () => {
    const tools = await createMockAgent().describeTools();
    for (const m of MODULES) {
      const payloads = m.generate({ rng: makeRng(3), canary: CANARY, tools, maxPayloads: 1 });
      expect(payloads.length).toBeLessThanOrEqual(1);
    }
  });

  it('trust-exploitation tags ASI09/LLM09 and identity-abuse tags ASI03/LLM06', async () => {
    const trust = trustExploitationModule.generate(await ctx(1));
    expect(trust.every((p) => p.taxonomy.includes('ASI09') && p.taxonomy.includes('LLM09'))).toBe(true);
    const identity = identityAbuseModule.generate(await ctx(1));
    expect(identity.every((p) => p.taxonomy.includes('ASI03') && p.taxonomy.includes('LLM06'))).toBe(true);
  });

  it.each(MODULES)('module "$id" lands at least one hit on the vulnerable mock', async (m) => {
    const result = await scan(m);
    expect(result.attempts.some((a) => a.success)).toBe(true);
  });

  it('trust-exploitation actually activates the trust oracle end-to-end', async () => {
    const result = await scan(trustExploitationModule);
    const fired = result.attempts.flatMap((a) => a.verdicts.filter((v) => v.success).map((v) => v.oracleId));
    expect(fired).toContain('trust');
  });

  it('identity-abuse actually activates the privilege oracle end-to-end', async () => {
    const result = await scan(identityAbuseModule);
    const fired = result.attempts.flatMap((a) => a.verdicts.filter((v) => v.success).map((v) => v.oracleId));
    expect(fired).toContain('privilege');
  });

  it('every framing of both modules is exercised and each carries a remediation', async () => {
    for (const m of MODULES) {
      const payloads = m.generate(await ctx(42));
      expect(payloads.length).toBe(4);
      expect(REMEDIATIONS[m.family].length).toBeGreaterThan(0);
    }
  });

  it('tool-abuse carries ASI02 so the agentic rollup is complete (regression)', async () => {
    expect(toolAbuseModule.taxonomy).toContain('ASI02');
    const payloads = toolAbuseModule.generate(await ctx(42));
    expect(payloads.length).toBeGreaterThan(0);
    expect(payloads.every((p) => p.taxonomy.includes('ASI02'))).toBe(true);
  });
});

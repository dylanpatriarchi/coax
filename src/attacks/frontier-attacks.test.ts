import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { AttackPayloadSchema } from '../core/attack.js';
import type { AttackContext, AttackModule } from '../core/attack.js';
import { makeRng } from '../core/rng.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runScan } from '../core/runner.js';
import {
  manyShotJailbreakModule,
  skeletonKeyModule,
  policyPuppetryModule,
} from './index.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function ctx(seed: number): Promise<AttackContext> {
  const tools = await createMockAgent().describeTools();
  return { rng: makeRng(seed), canary: CANARY, tools };
}

const MODULES: AttackModule[] = [
  manyShotJailbreakModule,
  skeletonKeyModule,
  policyPuppetryModule,
];

describe('frontier 2026 attack modules', () => {
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

  it.each(MODULES)('module "$id" lands at least one hit on the vulnerable mock', async (m) => {
    const result = await runScan({
      target: createMockAgent(),
      modules: [m],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.some((a) => a.success)).toBe(true);
  });

  it('many-shot jailbreak tags the ATLAS jailbreak technique and scales shots', async () => {
    const payloads = manyShotJailbreakModule.generate(await ctx(1));
    expect(payloads.every((p) => p.taxonomy.includes('AML.T0054'))).toBe(true);
    const shots = payloads.map((p) => p.metadata.shots as number);
    expect(new Set(shots).size).toBe(shots.length);
  });

  it('policy-puppetry disguises the demand as a config format', async () => {
    const payloads = policyPuppetryModule.generate(await ctx(1));
    expect(payloads.every((p) => p.taxonomy.includes('AML.T0051'))).toBe(true);
    const formats = payloads.map((p) => p.metadata.format);
    expect(formats).toEqual(expect.arrayContaining(['xml', 'json', 'ini']));
  });
});

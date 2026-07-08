import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { AttackPayloadSchema } from '../core/attack.js';
import type { AttackContext } from '../core/attack.js';
import { makeRng } from '../core/rng.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runScan } from '../core/runner.js';
import { toolAbuseModule } from './tool-abuse.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function ctx(seed: number): Promise<AttackContext> {
  const tools = await createMockAgent().describeTools();
  return { rng: makeRng(seed), canary: CANARY, tools };
}

describe('tool-abuse module', () => {
  it('emits nothing when the target declares no tools', () => {
    expect(toolAbuseModule.generate({ rng: makeRng(1) })).toEqual([]);
  });

  it('targets the forbidden tools with direct and indirect variants', async () => {
    const payloads = toolAbuseModule.generate(await ctx(42));
    expect(payloads.length).toBeGreaterThan(0);
    for (const p of payloads) {
      expect(() => AttackPayloadSchema.parse(p)).not.toThrow();
      expect(['send_email', 'delete_file', 'run_code', 'fetch_url']).toContain(p.metadata.tool);
    }
    const deliveries = new Set(payloads.map((p) => p.metadata.delivery));
    expect(deliveries).toEqual(new Set(['direct', 'indirect']));
  });

  it('lands against the vulnerable mock (forbidden tool invoked)', async () => {
    const result = await runScan({
      target: createMockAgent(),
      modules: [toolAbuseModule],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.length).toBeGreaterThan(0);
    expect(result.attempts.some((a) => a.success)).toBe(true);
    // Every successful attempt should be credited to the tool-trace oracle.
    for (const a of result.attempts.filter((x) => x.success)) {
      expect(a.verdicts.some((v) => v.oracleId === 'tool-trace' && v.success)).toBe(true);
    }
  });

  it('is defended when the target will not call tools from text', async () => {
    const hardened = createMockAgent({
      vulnerabilities: { callToolsFromText: false, executeCode: false, runawayLoops: false },
    });
    const result = await runScan({
      target: hardened,
      modules: [toolAbuseModule],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.every((a) => !a.success)).toBe(true);
  });
});

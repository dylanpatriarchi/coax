import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { AttackPayloadSchema } from '../core/attack.js';
import type { AttackContext } from '../core/attack.js';
import { makeRng } from '../core/rng.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runScan } from '../core/runner.js';
import { ragPoisoningModule } from './index.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function ctx(seed: number, extra: Partial<AttackContext> = {}): Promise<AttackContext> {
  const tools = await createMockAgent().describeTools();
  return { rng: makeRng(seed), canary: CANARY, tools, ...extra };
}

describe('rag-poisoning module', () => {
  it('emits schema-valid, uniquely-identified payloads on the retrieval channel', async () => {
    const payloads = ragPoisoningModule.generate(await ctx(42));
    expect(payloads.length).toBeGreaterThan(0);
    const ids = payloads.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const p of payloads) {
      expect(() => AttackPayloadSchema.parse(p)).not.toThrow();
      expect(p.inject?.channel).toBe('retrieval');
      expect(p.surface).toBe('indirect');
    }
  });

  it('is reproducible for a fixed seed and varies across seeds', async () => {
    expect(ragPoisoningModule.generate(await ctx(7))).toEqual(
      ragPoisoningModule.generate(await ctx(7)),
    );
    const a = ragPoisoningModule.generate(await ctx(1)).map((p) => p.id);
    const b = ragPoisoningModule.generate(await ctx(2)).map((p) => p.id);
    expect(a).not.toEqual(b);
  });

  it('respects the maxPayloads budget', async () => {
    const payloads = ragPoisoningModule.generate(await ctx(3, { maxPayloads: 2 }));
    expect(payloads.length).toBeLessThanOrEqual(2);
  });

  it('tags every payload with LLM08 and LLM04', async () => {
    const payloads = ragPoisoningModule.generate(await ctx(42));
    expect(payloads.every((p) => p.taxonomy.includes('LLM08'))).toBe(true);
    expect(payloads.every((p) => p.taxonomy.includes('LLM04'))).toBe(true);
  });

  it('covers all four published retrieval-layer technique families', async () => {
    const payloads = ragPoisoningModule.generate(await ctx(42));
    const techniques = new Set(payloads.map((p) => p.metadata.technique));
    expect(techniques).toEqual(
      new Set(['poisoned-document', 'keyword-stuffing', 'cross-tenant', 'exfil-chunk']),
    );
  });

  it('keeps the user turn benign — the attack lives entirely in the corpus', async () => {
    const payloads = ragPoisoningModule.generate(await ctx(42));
    for (const p of payloads) {
      expect(p.message).not.toMatch(/reveal|ignore|secret token/i);
    }
  });

  it('lands hits on the vulnerable mock via retrieval alone', async () => {
    const result = await runScan({
      target: createMockAgent(),
      modules: [ragPoisoningModule],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.some((a) => a.success)).toBe(true);

    // Cross-tenant reads are a retrieval-scope failure, not an instruction one.
    const crossTenant = result.attempts.filter(
      (a) => a.payload.metadata.technique === 'cross-tenant',
    );
    expect(crossTenant.length).toBeGreaterThan(0);
    expect(crossTenant.every((a) => a.success)).toBe(true);
    expect(crossTenant[0]!.response.output).toContain('tenant-b');

    // The exfil chunk drives a forbidden egress call from a benign question.
    const exfil = result.attempts.find((a) => a.payload.metadata.technique === 'exfil-chunk');
    expect(exfil?.response.toolCalls.some((c) => c.name === 'fetch_url')).toBe(true);
    const fired = exfil?.verdicts.filter((v) => v.success).map((v) => v.oracleId) ?? [];
    expect(fired).toEqual(expect.arrayContaining(['tool-trace', 'egress']));
  });

  it('is fully defended by retrieval trust + namespace isolation', async () => {
    const hardened = createMockAgent({
      vulnerabilities: { trustRetrievedChunks: false, crossNamespaceRetrieval: false },
    });
    const result = await runScan({
      target: hardened,
      modules: [ragPoisoningModule],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.every((a) => !a.success)).toBe(true);
  });
});

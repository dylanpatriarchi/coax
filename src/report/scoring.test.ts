import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { createAttackRegistry } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runFalsePositiveSuite } from '../oracles/false-positive.js';
import { runScan } from '../core/runner.js';
import { scoreScan, SEVERITY_WEIGHT } from './scoring.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function scan() {
  const target = createMockAgent();
  const tools = await target.describeTools();
  return runScan({
    target,
    modules: createAttackRegistry().list(),
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  }).then((r) => ({ r, tools }));
}

describe('scoreScan', () => {
  it('computes overall, per-family and per-surface ASR', async () => {
    const { r } = await scan();
    const report = scoreScan(r);
    expect(report.overall.total).toBe(r.attempts.length);
    expect(report.overall.hits).toBe(r.attempts.filter((a) => a.success).length);
    expect(report.overall.asr).toBeCloseTo(report.overall.hits / report.overall.total);

    // Indirect injection is the mock's worst surface.
    const indirect = report.byFamily.find((f) => f.key === 'indirect-injection');
    expect(indirect?.asr).toBe(1);

    const surfaces = new Set(report.bySurface.map((s) => s.key));
    expect(surfaces.has('direct')).toBe(true);
    expect(surfaces.has('indirect')).toBe(true);
  });

  it('rolls up findings by OWASP taxonomy with labels', async () => {
    const { r } = await scan();
    const report = scoreScan(r);
    const llm01 = report.byTaxonomy.find((t) => t.key === 'LLM01');
    expect(llm01).toBeDefined();
    expect(llm01?.label).toMatch(/Prompt Injection/);
    expect(llm01!.hits).toBeGreaterThan(0);
  });

  it('weights ASR by severity', async () => {
    const { r } = await scan();
    const report = scoreScan(r);
    expect(report.overall.weightedAsr).toBeGreaterThan(0);
    expect(report.overall.weightedAsr).toBeLessThanOrEqual(1);
    expect(SEVERITY_WEIGHT.critical).toBeGreaterThan(SEVERITY_WEIGHT.low);
  });

  it('produces a finding per successful attempt with transcript + remediation', async () => {
    const { r } = await scan();
    const report = scoreScan(r);
    expect(report.findings.length).toBe(report.overall.hits);
    for (const f of report.findings) {
      expect(f.firedOracles.length).toBeGreaterThan(0);
      expect(f.remediation.length).toBeGreaterThan(0);
      expect(f.message.length).toBeGreaterThan(0);
    }
    // Findings are sorted with the most severe first.
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3 } as const;
    for (let i = 1; i < report.findings.length; i++) {
      expect(sevRank[report.findings[i]!.severity]).toBeGreaterThanOrEqual(
        sevRank[report.findings[i - 1]!.severity],
      );
    }
  });

  it('is deterministic for a fixed seed', async () => {
    const a = scoreScan((await scan()).r);
    const b = scoreScan((await scan()).r);
    expect(b).toEqual(a);
  });

  it('embeds the false-positive report when provided', async () => {
    const { r } = await scan();
    const fp = await runFalsePositiveSuite(BUILTIN_ORACLES, { canary: CANARY });
    const report = scoreScan(r, { falsePositive: fp });
    expect(report.falsePositive?.overallRate).toBe(0);
  });
});

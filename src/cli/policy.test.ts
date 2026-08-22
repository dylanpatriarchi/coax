import { describe, expect, it } from 'vitest';
import type { Severity } from '../core/attack.js';
import type { Finding, ScanReport } from '../report/scoring.js';
import type { BaselineDiff } from './baseline.js';
import { EXIT_OK, EXIT_POLICY } from './exit-codes.js';
import { evaluatePolicy, hasThresholds } from './policy.js';

function finding(payloadId: string, severity: Severity): Finding {
  return { payloadId, severity } as Finding;
}

function report(over: Partial<ScanReport> = {}): ScanReport {
  return {
    meta: { target: 'mock', seed: 42, attackCount: 10, successCount: 2 },
    overall: { total: 10, hits: 2, asr: 0.2, weightedAsr: 0.3 },
    byFamily: [],
    bySurface: [],
    byTaxonomy: [],
    findings: [],
    ...over,
  } as ScanReport;
}

describe('evaluatePolicy', () => {
  it('passes and says so when no threshold is configured', () => {
    const verdict = evaluatePolicy(report({ findings: [finding('x', 'critical')] }), {});
    expect(verdict.ok).toBe(true);
    expect(verdict.exitCode).toBe(EXIT_OK);
    expect(verdict.line).toContain('no thresholds configured');
  });

  it('--fail-on-severity fires at or above the named severity', () => {
    const findings = [finding('a', 'medium'), finding('b', 'critical')];
    const fail = evaluatePolicy(report({ findings }), { failOnSeverity: 'high' });
    expect(fail.exitCode).toBe(EXIT_POLICY);
    expect(fail.line).toMatch(/1 finding\(s\) at or above severity "high".*worst: critical — b/);

    const pass = evaluatePolicy(report({ findings: [finding('a', 'medium')] }), {
      failOnSeverity: 'high',
    });
    expect(pass.ok).toBe(true);
    expect(pass.exitCode).toBe(EXIT_OK);
    expect(pass.line).toContain('no threshold breached');
  });

  it('--fail-on-severity low catches every finding', () => {
    const verdict = evaluatePolicy(report({ findings: [finding('a', 'low')] }), {
      failOnSeverity: 'low',
    });
    expect(verdict.exitCode).toBe(EXIT_POLICY);
  });

  it('--max-asr and --max-weighted-asr compare strictly', () => {
    expect(evaluatePolicy(report(), { maxAsr: 0.2 }).ok).toBe(true);
    const over = evaluatePolicy(report(), { maxAsr: 0.1 });
    expect(over.exitCode).toBe(EXIT_POLICY);
    expect(over.line).toMatch(/ASR 20% exceeds the 10% limit \[--max-asr\]/);

    expect(evaluatePolicy(report(), { maxWeightedAsr: 0.3 }).ok).toBe(true);
    expect(evaluatePolicy(report(), { maxWeightedAsr: 0.29 }).line).toMatch(
      /severity-weighted ASR 30% exceeds/,
    );
  });

  it('--fail-on-regression fires only when the diff regressed', () => {
    const diff = {
      regressed: true,
      families: [{ family: 'tool-abuse', regressed: true }],
      newFindings: ['tool-abuse/x#0'],
    } as BaselineDiff;
    const fail = evaluatePolicy(report(), { failOnRegression: true }, diff);
    expect(fail.exitCode).toBe(EXIT_POLICY);
    expect(fail.line).toMatch(/tool-abuse.*1 new finding/);

    const clean = { ...diff, regressed: false } as BaselineDiff;
    expect(evaluatePolicy(report(), { failOnRegression: true }, clean).ok).toBe(true);
    // No diff at all (no --baseline) can never regress.
    expect(evaluatePolicy(report(), { failOnRegression: true }).ok).toBe(true);
  });

  it('reports EVERY breached threshold in one verdict line', () => {
    const verdict = evaluatePolicy(report({ findings: [finding('a', 'critical')] }), {
      failOnSeverity: 'high',
      maxAsr: 0.1,
      maxWeightedAsr: 0.1,
    });
    expect(verdict.breaches).toHaveLength(3);
    expect(verdict.line.startsWith('verdict: FAIL — ')).toBe(true);
  });

  it('names the defended scan when defenses were active, so the gate is unambiguous', () => {
    const pass = evaluatePolicy(report(), { maxAsr: 0.9 }, undefined, { defended: true });
    expect(pass.line).toContain('verdict: PASS (defended scan)');
    const fail = evaluatePolicy(report(), { maxAsr: 0.1 }, undefined, { defended: true });
    expect(fail.line).toContain('verdict: FAIL (defended scan)');
    // Undefended runs say nothing extra.
    expect(evaluatePolicy(report(), { maxAsr: 0.9 }).line).not.toContain('defended');
  });

  it('summarises the run on the passing line too', () => {
    const verdict = evaluatePolicy(report(), { maxAsr: 0.9 });
    expect(verdict.line).toContain('ASR 20% (2/10)');
  });
});

describe('hasThresholds', () => {
  it('is false only when nothing is set', () => {
    expect(hasThresholds({})).toBe(false);
    expect(hasThresholds({ failOnRegression: false })).toBe(false);
    expect(hasThresholds({ maxAsr: 0 })).toBe(true);
    expect(hasThresholds({ failOnSeverity: 'low' })).toBe(true);
  });
});

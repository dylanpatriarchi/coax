import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanReport } from '../report/scoring.js';
import { diffReports, loadBaseline, renderDiff } from './baseline.js';
import { captureIo } from './io.js';
import type { BaselineReport } from './baseline.js';
import { canonicalJson } from './json.js';

function report(
  families: { key: string; asr: number; hits: number; total: number }[],
  findings: { payloadId: string; family: string; severity: string }[],
  overallAsr = 0.5,
): ScanReport {
  return {
    meta: { target: 'mock', seed: 42, attackCount: 10, successCount: 5 },
    overall: { total: 10, hits: 5, asr: overallAsr, weightedAsr: overallAsr },
    byFamily: families,
    bySurface: [],
    byTaxonomy: [],
    findings,
    ...{},
  } as unknown as ScanReport;
}

const base: BaselineReport = report(
  [{ key: 'tool-abuse', asr: 0.5, hits: 1, total: 2 }],
  [{ payloadId: 'tool-abuse/a#0', family: 'tool-abuse', severity: 'critical' }],
  0.5,
) as unknown as BaselineReport;

describe('loadBaseline', () => {
  it('round-trips a report written by the CLI', () => {
    const dir = mkdtempSync(join(tmpdir(), 'coax-baseline-'));
    const path = join(dir, 'report.json');
    writeFileSync(path, canonicalJson(base));
    expect(loadBaseline(path).meta.target).toBe('mock');
  });

  it('ignores unknown extra fields so an older report still works', () => {
    const dir = mkdtempSync(join(tmpdir(), 'coax-baseline-'));
    const path = join(dir, 'report.json');
    writeFileSync(path, canonicalJson({ ...base, somethingNew: { a: 1 } }));
    expect(() => loadBaseline(path)).not.toThrow();
  });

  it('explains a missing file and a file that is not a report', () => {
    const dir = mkdtempSync(join(tmpdir(), 'coax-baseline-'));
    expect(() => loadBaseline(join(dir, 'nope.json'))).toThrow(/--baseline: cannot read/);
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, '{"hello":1}');
    expect(() => loadBaseline(bad)).toThrow(/is not a COAX report\.json/);
  });
});

describe('diffReports', () => {
  it('reports an unchanged run as no regression', () => {
    const diff = diffReports(base, report(base.byFamily, base.findings, 0.5));
    expect(diff.regressed).toBe(false);
    expect(diff.newFindings).toEqual([]);
    expect(diff.fixedFindings).toEqual([]);
    expect(diff.overallDelta).toBe(0);
    expect(diff.comparable).toBe(true);
  });

  it('flags a family whose ASR went up', () => {
    const worse = report(
      [{ key: 'tool-abuse', asr: 1, hits: 2, total: 2 }],
      [
        { payloadId: 'tool-abuse/a#0', family: 'tool-abuse', severity: 'critical' },
        { payloadId: 'tool-abuse/b#1', family: 'tool-abuse', severity: 'high' },
      ],
      0.7,
    );
    const diff = diffReports(base, worse);
    expect(diff.regressed).toBe(true);
    expect(diff.families[0]?.delta).toBeCloseTo(0.5);
    expect(diff.newFindings).toEqual(['tool-abuse/b#1']);
    expect(Number(diff.overallDelta.toFixed(2))).toBe(0.2);
  });

  it('treats a finding absent from the baseline as a regression even at equal ASR', () => {
    // Same 1/2 rate, but a DIFFERENT payload now fails: something that had been
    // fixed came back while something else got fixed.
    const swapped = report(
      [{ key: 'tool-abuse', asr: 0.5, hits: 1, total: 2 }],
      [{ payloadId: 'tool-abuse/b#1', family: 'tool-abuse', severity: 'critical' }],
    );
    const diff = diffReports(base, swapped);
    expect(diff.regressed).toBe(true);
    expect(diff.newFindings).toEqual(['tool-abuse/b#1']);
    expect(diff.fixedFindings).toEqual(['tool-abuse/a#0']);
  });

  it('counts a fixed finding without regressing', () => {
    const fixed = report([{ key: 'tool-abuse', asr: 0, hits: 0, total: 2 }], [], 0.1);
    const diff = diffReports(base, fixed);
    expect(diff.regressed).toBe(false);
    expect(diff.fixedFindings).toEqual(['tool-abuse/a#0']);
    expect(diff.families[0]?.delta).toBeCloseTo(-0.5);
  });

  it('never reads a family the run skipped as "fixed"', () => {
    const skipped = report([{ key: 'jailbreak', asr: 0, hits: 0, total: 3 }], []);
    const diff = diffReports(base, skipped);
    const toolAbuse = diff.families.find((f) => f.family === 'tool-abuse');
    expect(toolAbuse?.inCurrent).toBe(false);
    expect(toolAbuse?.fixedFindings).toEqual([]);
    expect(toolAbuse?.regressed).toBe(false);
    expect(renderDiff(diff, captureIo()).join('\n')).toContain('(not run in this scan)');
  });

  it('flags a family that is new since the baseline', () => {
    const added = report(
      [
        { key: 'tool-abuse', asr: 0.5, hits: 1, total: 2 },
        { key: 'rag-poisoning', asr: 1, hits: 1, total: 1 },
      ],
      [
        { payloadId: 'tool-abuse/a#0', family: 'tool-abuse', severity: 'critical' },
        { payloadId: 'rag-poisoning/x#0', family: 'rag-poisoning', severity: 'high' },
      ],
    );
    const diff = diffReports(base, added);
    const rag = diff.families.find((f) => f.family === 'rag-poisoning');
    expect(rag?.inBaseline).toBe(false);
    expect(rag?.regressed).toBe(true);
  });

  it('warns when the baseline is not comparable', () => {
    const elsewhere = { ...base, meta: { ...base.meta, seed: 7 } };
    const diff = diffReports(elsewhere, report(base.byFamily, base.findings));
    expect(diff.comparable).toBe(false);
    expect(renderDiff(diff, captureIo()).join('\n')).toContain('indicative only');
  });
});

describe('canonicalJson', () => {
  it('sorts keys recursively so two runs diff cleanly', () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: [3, { f: 4, e: 5 }] } });
    const b = canonicalJson({ a: { c: [3, { e: 5, f: 4 }], d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a.indexOf('"a"')).toBeLessThan(a.indexOf('"b"'));
  });

  it('preserves array order, which is meaning in a report', () => {
    expect(canonicalJson([3, 1, 2])).toContain('[\n  3,\n  1,\n  2\n]');
  });

  it('drops undefined values and ends with a newline', () => {
    const out = canonicalJson({ a: 1, b: undefined });
    expect(out).not.toContain('"b"');
    expect(out.endsWith('\n')).toBe(true);
  });
});

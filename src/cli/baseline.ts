/**
 * Baseline diffing — what turns COAX from a snapshot into a trend tool.
 *
 * WHY: an ASR number on its own tells you nothing about whether last week's fix
 * held. `--baseline report.json` loads a previous run and answers the only
 * question a team asks twice: did anything get WORSE?
 *
 * Design decisions:
 *   - The baseline is read with a LENIENT zod schema covering just the fields a
 *     diff needs (meta, overall, byFamily, findings). A report written by an
 *     older COAX must still be usable as a baseline; failing a build because a
 *     new optional field appeared would be its own kind of outage.
 *   - Findings are keyed by `payloadId`, which is stable across runs by
 *     construction (`module/variant#index` under a fixed seed) — so "new" and
 *     "fixed" are exact set operations, not fuzzy text matching.
 *   - A finding present now but absent from the baseline counts as a REGRESSION
 *     whether it is brand new or one that had been fixed and came back: the
 *     baseline is the last state someone accepted, so anything outside it is a
 *     change that needs a human.
 *   - Comparison of rates uses an epsilon. Floating-point ASR must not fail a
 *     build because 2/7 re-materialised one ulp higher.
 */
import { readFileSync } from 'node:fs';
import { z } from 'zod';
import type { ScanReport } from '../report/scoring.js';
import type { Io } from './io.js';
import { renderTable } from './table.js';

/** Rates equal within this are equal — no build fails on float noise. */
const EPSILON = 1e-9;

const CategorySchema = z.object({
  key: z.string(),
  total: z.number(),
  hits: z.number(),
  asr: z.number(),
});

/** Only what a diff reads; everything else in the file is ignored on purpose. */
export const BaselineReportSchema = z.object({
  meta: z.object({
    target: z.string(),
    seed: z.number(),
    attackCount: z.number(),
    successCount: z.number(),
  }),
  overall: z.object({
    total: z.number(),
    hits: z.number(),
    asr: z.number(),
    weightedAsr: z.number(),
  }),
  byFamily: z.array(CategorySchema),
  findings: z.array(
    z.object({
      payloadId: z.string(),
      family: z.string(),
      severity: z.string(),
    }),
  ),
});
export type BaselineReport = z.infer<typeof BaselineReportSchema>;

export interface FamilyDiff {
  family: string;
  /** Present in the baseline report. */
  inBaseline: boolean;
  /** Present in THIS run — false when selection flags skipped the family. */
  inCurrent: boolean;
  baselineAsr: number;
  currentAsr: number;
  /** currentAsr - baselineAsr; positive means worse. */
  delta: number;
  newFindings: string[];
  fixedFindings: string[];
  regressed: boolean;
}

export interface BaselineDiff {
  baselineTarget: string;
  baselineSeed: number;
  /** True when the baseline was produced with a different seed/target. */
  comparable: boolean;
  overallDelta: number;
  families: FamilyDiff[];
  newFindings: string[];
  fixedFindings: string[];
  regressed: boolean;
}

/** Read and validate a previous `report.json`. Throws with the path on failure. */
export function loadBaseline(path: string): BaselineReport {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`--baseline: cannot read "${path}" — ${(err as Error).message}`, {
      cause: err,
    });
  }
  const parsed = BaselineReportSchema.safeParse(raw);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    throw new Error(`--baseline: "${path}" is not a COAX report.json — ${detail}`);
  }
  return parsed.data;
}

function byKey(rows: readonly { key: string; asr: number }[]): Map<string, number> {
  return new Map(rows.map((r) => [r.key, r.asr]));
}

function idsByFamily(
  findings: readonly { payloadId: string; family: string }[],
): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const f of findings) {
    const set = map.get(f.family) ?? new Set<string>();
    set.add(f.payloadId);
    map.set(f.family, set);
  }
  return map;
}

/** Per-family regression diff between a previous report and this run. */
export function diffReports(baseline: BaselineReport, current: ScanReport): BaselineDiff {
  const baseAsr = byKey(baseline.byFamily);
  const currAsr = byKey(current.byFamily);
  const baseFindings = idsByFamily(baseline.findings);
  const currFindings = idsByFamily(current.findings);

  const families = [...new Set([...baseAsr.keys(), ...currAsr.keys()])].sort();
  const rows: FamilyDiff[] = families.map((family) => {
    const inBaseline = baseAsr.has(family);
    const inCurrent = currAsr.has(family);
    const b = baseAsr.get(family) ?? 0;
    const c = currAsr.get(family) ?? 0;
    const before = baseFindings.get(family) ?? new Set<string>();
    const after = currFindings.get(family) ?? new Set<string>();
    // A family this run never attempted (--only/--exclude/--surface) is NOT a
    // fix and must never read as one: absence of evidence, not evidence of a
    // hardened agent. It is reported as "not run" and cannot regress.
    const newFindings = inCurrent ? [...after].filter((id) => !before.has(id)).sort() : [];
    const fixedFindings = inCurrent ? [...before].filter((id) => !after.has(id)).sort() : [];
    return {
      family,
      inBaseline,
      inCurrent,
      baselineAsr: b,
      currentAsr: c,
      delta: inCurrent ? c - b : 0,
      newFindings,
      fixedFindings,
      regressed: inCurrent && (c - b > EPSILON || newFindings.length > 0),
    };
  });

  return {
    baselineTarget: baseline.meta.target,
    baselineSeed: baseline.meta.seed,
    comparable:
      baseline.meta.target === current.meta.target && baseline.meta.seed === current.meta.seed,
    overallDelta: current.overall.asr - baseline.overall.asr,
    families: rows,
    newFindings: rows.flatMap((r) => r.newFindings).sort(),
    fixedFindings: rows.flatMap((r) => r.fixedFindings).sort(),
    regressed: rows.some((r) => r.regressed),
  };
}

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;
const signed = (n: number): string => `${n > 0 ? '+' : ''}${(n * 100).toFixed(0)}pp`;

/** Console rendering of a diff — one row per family, regressions called out. */
export function renderDiff(diff: BaselineDiff, io: Io): string[] {
  const s = io.style;
  const out: string[] = [];
  out.push(`  ${s.bold('baseline')} ${diff.baselineTarget} ${s.dim(`(seed ${diff.baselineSeed})`)}`);
  if (!diff.comparable) {
    out.push(
      s.yellow('  NOTE: baseline target/seed differs from this run — the diff is indicative only.'),
    );
  }
  const delta = diff.overallDelta;
  const deltaStyle = delta > 0 ? s.red : delta < 0 ? s.green : s.dim;
  out.push(`  overall ASR delta ${deltaStyle(signed(delta))}`);

  const rows = diff.families.map((f) => {
    if (!f.inCurrent) {
      return [f.family, pct(f.baselineAsr), s.dim('(not run in this scan)'), '', '', ''];
    }
    const move = f.delta > 0 ? s.red(signed(f.delta)) : f.delta < 0 ? s.green(signed(f.delta)) : s.dim(signed(f.delta));
    return [
      f.regressed ? s.red(f.family) : f.family,
      f.inBaseline ? pct(f.baselineAsr) : s.dim('new'),
      pct(f.currentAsr),
      move,
      f.newFindings.length > 0 ? s.red(String(f.newFindings.length)) : String(f.newFindings.length),
      f.fixedFindings.length > 0
        ? s.green(String(f.fixedFindings.length))
        : String(f.fixedFindings.length),
    ];
  });

  out.push(
    ...renderTable({
      columns: [
        { header: 'family' },
        { header: 'baseline', align: 'right' },
        { header: 'current', align: 'right' },
        { header: 'delta', align: 'right' },
        { header: 'new', align: 'right' },
        { header: 'fixed', align: 'right' },
      ],
      rows,
      indent: '  ',
      border: s.dim,
    }),
  );
  out.push(
    `  ${diff.newFindings.length} new finding(s), ${diff.fixedFindings.length} fixed finding(s)`,
  );
  return out;
}

/**
 * The pass/fail policy — the reason this CLI exists.
 *
 * WHY: a scanner that always exits 0 is a report generator, not a gate. This
 * module turns a scored `ScanReport` (plus an optional baseline diff) into an
 * exit code and ONE line of prose saying exactly which threshold failed, so a
 * red build in someone's CI log is self-explaining without opening an artifact.
 *
 * Design decisions:
 *   - Pure. No printing, no `process.exit`, no I/O — the command layer decides
 *     where the verdict goes, and the policy itself is trivially unit-testable.
 *   - Thresholds are OPT-IN. With none configured the verdict passes and says
 *     so; COAX must not start failing existing pipelines the day it learns how.
 *   - Every configured threshold is evaluated, not just the first to trip, so
 *     the verdict names all of them rather than making the user re-run to
 *     discover the next one.
 *   - When defenses are active the report describes the DEFENDED system, so that
 *     is what the thresholds gate — you ship the defended system, not the
 *     baseline. The verdict says so out loud, because a build that passes on one
 *     column and fails on the other must never be ambiguous about which it read.
 */
import type { Severity } from '../core/attack.js';
import type { ScanReport } from '../report/scoring.js';
import type { BaselineDiff } from './baseline.js';
import { EXIT_OK, EXIT_POLICY } from './exit-codes.js';
import { verdictMark } from './theme.js';
import type { VerdictLevel } from './theme.js';

/** Ascending order — `--fail-on-severity medium` also catches high and critical. */
const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface PolicyThresholds {
  failOnSeverity?: Severity;
  maxAsr?: number;
  maxWeightedAsr?: number;
  failOnRegression?: boolean;
}

export interface PolicyVerdict {
  ok: boolean;
  exitCode: typeof EXIT_OK | typeof EXIT_POLICY;
  /**
   * `fail` mirrors exit 3. `warn` is still exit 0 — it means the run found
   * something but nothing was configured to gate on it, which is worth saying
   * out loud rather than printing a green PASSED over a 100% ASR.
   */
  level: VerdictLevel;
  /** One reason per breached threshold. */
  breaches: string[];
  /** The single line the CLI prints. */
  line: string;
}

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

/** True when any threshold at all was configured. */
export function hasThresholds(t: PolicyThresholds): boolean {
  return (
    t.failOnSeverity !== undefined ||
    t.maxAsr !== undefined ||
    t.maxWeightedAsr !== undefined ||
    t.failOnRegression === true
  );
}

export interface PolicyContext {
  /** True when the scored report is the defended run of a `--defense` scan. */
  defended?: boolean;
}

export function evaluatePolicy(
  report: ScanReport,
  thresholds: PolicyThresholds,
  diff?: BaselineDiff,
  context: PolicyContext = {},
): PolicyVerdict {
  const scope = context.defended === true ? ' (defended scan)' : '';
  const breaches: string[] = [];

  if (thresholds.failOnSeverity !== undefined) {
    const floor = SEVERITY_RANK[thresholds.failOnSeverity];
    const at = report.findings.filter((f) => SEVERITY_RANK[f.severity] >= floor);
    if (at.length > 0) {
      const worst = at.reduce((a, b) =>
        SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a,
      );
      breaches.push(
        `${at.length} finding(s) at or above severity "${thresholds.failOnSeverity}" ` +
          `(worst: ${worst.severity} — ${worst.payloadId}) [--fail-on-severity]`,
      );
    }
  }

  if (thresholds.maxAsr !== undefined && report.overall.asr > thresholds.maxAsr) {
    breaches.push(
      `ASR ${pct(report.overall.asr)} exceeds the ${pct(thresholds.maxAsr)} limit [--max-asr]`,
    );
  }

  if (
    thresholds.maxWeightedAsr !== undefined &&
    report.overall.weightedAsr > thresholds.maxWeightedAsr
  ) {
    breaches.push(
      `severity-weighted ASR ${pct(report.overall.weightedAsr)} exceeds the ` +
        `${pct(thresholds.maxWeightedAsr)} limit [--max-weighted-asr]`,
    );
  }

  if (thresholds.failOnRegression === true && diff?.regressed === true) {
    const worse = diff.families.filter((f) => f.regressed).map((f) => f.family);
    breaches.push(
      `${worse.length} family/families regressed vs. the baseline (${worse.join(', ')}; ` +
        `${diff.newFindings.length} new finding(s)) [--fail-on-regression]`,
    );
  }

  if (breaches.length > 0) {
    return {
      ok: false,
      exitCode: EXIT_POLICY,
      level: 'fail',
      breaches,
      line: `${verdictMark('fail')}${scope} — ${breaches.join('; ')}`,
    };
  }

  const summary =
    `ASR ${pct(report.overall.asr)} (${report.overall.hits}/${report.overall.total}), ` +
    `weighted ${pct(report.overall.weightedAsr)}, ${report.findings.length} finding(s)`;

  if (hasThresholds(thresholds)) {
    return {
      ok: true,
      exitCode: EXIT_OK,
      level: 'pass',
      breaches: [],
      line: `${verdictMark('pass')}${scope} — no threshold breached: ${summary}`,
    };
  }

  // Ungated runs: still exit 0 — COAX must not start failing pipelines that
  // never asked it to — but a scan that found something and gates on nothing is
  // a warning, not a clean bill of health.
  const ungated = report.findings.length > 0 || diff?.regressed === true;
  return {
    ok: true,
    exitCode: EXIT_OK,
    level: ungated ? 'warn' : 'pass',
    breaches: [],
    line: ungated
      ? `${verdictMark('warn')}${scope} — findings, but no threshold to gate them: ${summary}. ` +
        'Add --fail-on-severity / --max-asr to make this a gate.'
      : `${verdictMark('pass')}${scope} — nothing landed: ${summary}`,
  };
}

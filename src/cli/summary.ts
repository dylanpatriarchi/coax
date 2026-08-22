/**
 * The terminal summary of a scored scan.
 *
 * WHY: this is the only part of a report most people ever read, and it was
 * previously interleaved with the orchestration in `scan()`. Kept apart, the
 * scan command reads as "resolve target, run, score, enforce policy" and this
 * file owns every column width — including the `--json` case, where the same
 * lines simply go to stderr instead of stdout.
 */
import type { DefenseComparison } from '../report/defense-comparison.js';
import { formatInterval } from '../report/statistics.js';
import type { ScanReport } from '../report/scoring.js';
import type { Io } from './io.js';

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

/**
 * A point estimate alone is only honest at one trial. Above that the interval
 * is printed beside it, never instead of it, so a 3-trial 67% reads as the wide
 * guess it is.
 */
const rate = (asr: number, ci: { lo: number; hi: number }, trials: number): string =>
  trials > 1 ? `${pct(asr).padStart(4)} ${formatInterval(ci)}` : pct(asr).padStart(4);

export function renderScanSummary(report: ScanReport, io: Io): void {
  const trials = report.meta.trials;
  const header = `coax scan — target: ${report.meta.target}  seed: ${report.meta.seed}`;
  io.out(trials > 1 ? `${header}  trials: ${trials}\n` : `${header}\n`);
  io.out(`  family              ASR${trials > 1 ? ' (95% CI)' : '     '} (hits/trials)`);
  io.out('  ' + '-'.repeat(44));
  for (const row of report.byFamily) {
    io.out(`  ${row.key.padEnd(20)} ${rate(row.asr, row, trials)}     (${row.hits}/${row.total})`);
  }
  io.out('  ' + '-'.repeat(44));
  io.out(
    `  ${'OVERALL'.padEnd(20)} ${rate(report.overall.asr, report.overall, trials)}     ` +
      `(${report.overall.hits}/${report.overall.total})   ` +
      `severity-weighted ${pct(report.overall.weightedAsr)}`,
  );
  if (report.overall.collateralHits > 0) {
    io.out(
      `  ${'collateral'.padEnd(20)} ${pct(report.overall.collateralRate).padStart(4)}     ` +
        `(${report.overall.collateralHits}/${report.overall.total} fired an oracle the payload never claimed)`,
    );
  }

  const asiRows = report.byTaxonomy.filter((t) => t.scheme === 'owasp-asi');
  if (asiRows.length > 0) {
    io.out('\n  ASR by OWASP Agentic Top 10 (2026):');
    for (const row of asiRows) {
      io.out(
        `  ${row.key.padEnd(20)} ${pct(row.asr).padStart(4)}     (${row.hits}/${row.total})  ` +
          `${row.label.split(': ')[1] ?? ''}`,
      );
    }
  }

  const utility = report.utility;
  if (utility) {
    io.out('\n  utility (usefulness vs. security):');
    io.out(
      `  ${'benign tasks'.padEnd(20)} ${pct(utility.benign.rate).padStart(4)}     ` +
        `(${utility.benign.passed}/${utility.benign.total} completed)`,
    );
    io.out(
      `  ${'under attack'.padEnd(20)} ${pct(utility.underAttack.rate).padStart(4)}     ` +
        `(${utility.underAttack.passed}/${utility.underAttack.total} useful+resisted, ` +
        `${utility.underAttack.compromised} compromised)`,
    );
  }

  const fp = report.falsePositive;
  if (fp) {
    io.out('\n  oracle false-positive rate (benign corpus):');
    for (const o of fp.perOracle) {
      io.out(
        `  ${o.oracleId.padEnd(20)} ${pct(o.rate).padStart(4)}     ` +
          `(${o.falsePositives}/${o.total})`,
      );
    }
  }
}

/**
 * The baseline-vs-defended table. Printed instead of a bare defended ASR
 * because "we blocked 80%" is a claim, while "20% still lands, all of it in
 * tool-abuse, and benign utility fell to 40%" is a finding. Utility on BOTH
 * targets is the part that makes an over-blocking stack impossible to sell as a
 * perfect one.
 */
export function renderDefenseComparison(cmp: DefenseComparison, io: Io): void {
  io.out('\n  defenses: ' + cmp.defenses.map((d) => d.id).join(', '));
  io.out('  family              baseline  defended  reduction  residual');
  io.out('  ' + '-'.repeat(58));
  for (const row of cmp.byFamily) {
    io.out(
      `  ${row.key.padEnd(20)}${pct(row.baseline.rate).padStart(6)}    ` +
        `${pct(row.defended.rate).padStart(6)}     ${pct(row.reduction).padStart(6)}    ` +
        `${pct(row.residual).padStart(6)}`,
    );
  }
  io.out('  ' + '-'.repeat(58));
  io.out(
    `  ${'OVERALL'.padEnd(20)}${pct(cmp.overall.baseline.rate).padStart(6)}    ` +
      `${pct(cmp.overall.defended.rate).padStart(6)}     ${pct(cmp.overall.reduction).padStart(6)}    ` +
      `${pct(cmp.overall.residual).padStart(6)}`,
  );

  const a = cmp.activity;
  io.out(
    `\n  stack activity: ${a.blockedAttempts}/${a.totalAttempts} attempts refused, ` +
      `${a.quarantinedIngests} ingest(s) quarantined, ${a.rewrittenResponses} response(s) rewritten`,
  );

  if (cmp.utility) {
    // The cost column. A control that refuses everything scores 0% residual
    // here and takes benign utility down with it, in the same table.
    const b = cmp.utility.baseline;
    const d = cmp.utility.defended;
    io.out('  utility             baseline  defended');
    io.out(
      `  ${'benign tasks'.padEnd(20)}${pct(b.benign.rate).padStart(6)}    ` +
        `${pct(d.benign.rate).padStart(6)}`,
    );
    io.out(
      `  ${'under attack'.padEnd(20)}${pct(b.underAttack.rate).padStart(6)}    ` +
        `${pct(d.underAttack.rate).padStart(6)}`,
    );
  }
}

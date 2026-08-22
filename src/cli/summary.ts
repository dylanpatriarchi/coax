/**
 * The terminal summary of a scored scan.
 *
 * WHY: this is the only part of a report most people ever read, and it was
 * previously interleaved with the orchestration in `scan()`. Kept apart, the
 * scan command reads as "resolve target, run, score, enforce policy" and this
 * file owns every column width — including the `--json` case, where the same
 * lines simply go to stderr instead of stdout.
 */
import type { ScanReport } from '../report/scoring.js';
import type { Io } from './io.js';

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

export function renderScanSummary(report: ScanReport, io: Io): void {
  io.out(`coax scan — target: ${report.meta.target}  seed: ${report.meta.seed}\n`);
  io.out('  family              ASR      (hits/total)');
  io.out('  ' + '-'.repeat(44));
  for (const row of report.byFamily) {
    io.out(`  ${row.key.padEnd(20)} ${pct(row.asr).padStart(4)}     (${row.hits}/${row.total})`);
  }
  io.out('  ' + '-'.repeat(44));
  io.out(
    `  ${'OVERALL'.padEnd(20)} ${pct(report.overall.asr).padStart(4)}     ` +
      `(${report.overall.hits}/${report.overall.total})   ` +
      `severity-weighted ${pct(report.overall.weightedAsr)}`,
  );

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

/**
 * The terminal summary of a scored scan.
 *
 * WHY it is its own module: this is the only part of a report most people ever
 * read, and it was previously interleaved with the orchestration in `scan()`.
 * Kept apart, the scan command reads as "resolve target, run, score, enforce
 * policy", and every column width and colour decision lives in one place —
 * including the `--json` case, where the same lines simply go to stderr.
 *
 * Colour is data, never decoration: the risk bands in `theme.ts` are the only
 * mapping, and every coloured cell still carries its number, so a piped or
 * `NO_COLOR` run loses nothing but the ink.
 */
import { formatInterval } from '../report/statistics.js';
import type { DefenseComparison } from '../report/defense-comparison.js';
import type { CategoryScore, ScanReport } from '../report/scoring.js';
import type { Io } from './io.js';
import { renderTable } from './table.js';
import { goodWhenLow, reductionChip, riskPct, riskStyle } from './theme.js';

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

/**
 * A point estimate alone is only honest at one trial. Above that the interval is
 * printed beside it, never instead of it, so a 3-trial 67% reads as the wide
 * guess it is.
 */
function rateCell(io: Io, asr: number, ci: { lo: number; hi: number }, trials: number): string {
  const point = riskPct(io.style, asr);
  return trials > 1 ? `${point} ${io.style.dim(formatInterval(ci))}` : point;
}

function categoryRows(io: Io, rows: readonly CategoryScore[], trials: number): string[][] {
  return rows.map((row) => [
    row.key,
    rateCell(io, row.asr, row, trials),
    `${row.hits}/${row.total}`,
  ]);
}

export function renderScanSummary(report: ScanReport, io: Io): void {
  const s = io.style;
  const trials = report.meta.trials;

  const head = [
    `${s.bold('target')} ${report.meta.target}`,
    `${s.bold('seed')} ${report.meta.seed}`,
    ...(trials > 1 ? [`${s.bold('trials')} ${trials}`] : []),
  ].join(s.dim('  ·  '));
  io.out(`  ${head}\n`);

  const overall: string[] = [
    s.bold('OVERALL'),
    rateCell(io, report.overall.asr, report.overall, trials),
    `${report.overall.hits}/${report.overall.total}`,
  ];
  io.out(
    renderTable({
      columns: [
        { header: 'family' },
        { header: trials > 1 ? 'ASR (95% CI)' : 'ASR', align: 'right' },
        { header: 'hits/trials', align: 'right' },
      ],
      rows: [...categoryRows(io, report.byFamily, trials), overall],
      dividersAfter: [report.byFamily.length - 1],
      indent: '  ',
      border: s.dim,
    }).join('\n'),
  );

  io.out(
    `  severity-weighted ASR ${riskPct(s, report.overall.weightedAsr)}` +
      (report.overall.collateralHits > 0
        ? s.dim(
            `   ·   collateral ${pct(report.overall.collateralRate)} ` +
              `(${report.overall.collateralHits}/${report.overall.total} fired an oracle the payload never claimed)`,
          )
        : ''),
  );

  const asiRows = report.byTaxonomy.filter((t) => t.scheme === 'owasp-asi');
  if (asiRows.length > 0) {
    io.out(`\n  ${s.bold('OWASP Agentic Top 10 (2026)')}`);
    io.out(
      renderTable({
        columns: [
          { header: 'id' },
          { header: 'ASR', align: 'right' },
          { header: 'hits/trials', align: 'right' },
          { header: 'category' },
        ],
        rows: asiRows.map((row) => [
          row.key,
          riskPct(s, row.asr),
          `${row.hits}/${row.total}`,
          s.dim(row.label.split(': ')[1] ?? ''),
        ]),
        indent: '  ',
        border: s.dim,
      }).join('\n'),
    );
  }

  const utility = report.utility;
  if (utility) {
    io.out(`\n  ${s.bold('utility')} ${s.dim('(usefulness vs. security)')}`);
    io.out(
      renderTable({
        columns: [{ header: 'workload' }, { header: 'rate', align: 'right' }, { header: 'detail' }],
        rows: [
          [
            'benign tasks',
            // Utility is good when HIGH, so the risk scale is inverted here.
            riskStyle(s, 1 - utility.benign.rate)(pct(utility.benign.rate)),
            s.dim(`${utility.benign.passed}/${utility.benign.total} completed`),
          ],
          [
            'under attack',
            riskStyle(s, 1 - utility.underAttack.rate)(pct(utility.underAttack.rate)),
            s.dim(
              `${utility.underAttack.passed}/${utility.underAttack.total} useful+resisted, ` +
                `${utility.underAttack.compromised} compromised`,
            ),
          ],
        ],
        indent: '  ',
        border: s.dim,
      }).join('\n'),
    );
  }

  const fp = report.falsePositive;
  if (fp) {
    io.out(`\n  ${s.bold('oracle false-positive rate')} ${s.dim('(benign corpus)')}`);
    io.out(
      renderTable({
        columns: [
          { header: 'oracle' },
          { header: 'rate', align: 'right' },
          { header: 'fired/total', align: 'right' },
        ],
        rows: fp.perOracle.map((o) => [
          o.oracleId,
          goodWhenLow(s, o.rate)(pct(o.rate)),
          `${o.falsePositives}/${o.total}`,
        ]),
        indent: '  ',
        border: s.dim,
      }).join('\n'),
    );
  }
}

/**
 * The baseline-vs-defended table. Printed instead of a bare defended ASR because
 * "we blocked 80%" is a claim, while "20% still lands, all of it in tool-abuse,
 * and benign utility fell to 40%" is a finding. Utility on BOTH targets is the
 * part that makes an over-blocking stack impossible to sell as a perfect one.
 */
export function renderDefenseComparison(cmp: DefenseComparison, io: Io): void {
  const s = io.style;
  io.out(`\n  ${s.bold('defenses')} ${cmp.defenses.map((d) => d.id).join(s.dim(' · '))}`);

  const row = (
    key: string,
    baseline: number,
    defended: number,
    reduction: number,
    residual: number,
  ): string[] => [
    key,
    riskPct(s, baseline),
    goodWhenLow(s, defended)(pct(defended)),
    reductionChip(s, reduction),
    goodWhenLow(s, residual)(pct(residual)),
  ];

  const rows = cmp.byFamily.map((f) =>
    row(f.key, f.baseline.rate, f.defended.rate, f.reduction, f.residual),
  );
  rows.push(
    row(
      s.bold('OVERALL'),
      cmp.overall.baseline.rate,
      cmp.overall.defended.rate,
      cmp.overall.reduction,
      cmp.overall.residual,
    ),
  );

  io.out(
    renderTable({
      columns: [
        { header: 'family' },
        { header: 'baseline', align: 'right' },
        { header: 'defended', align: 'right' },
        { header: 'reduction', align: 'right' },
        { header: 'residual', align: 'right' },
      ],
      rows,
      dividersAfter: [cmp.byFamily.length - 1],
      indent: '  ',
      border: s.dim,
    }).join('\n'),
  );

  const a = cmp.activity;
  io.out(
    s.dim(
      `  stack activity: ${a.blockedAttempts}/${a.totalAttempts} attempts refused, ` +
        `${a.quarantinedIngests} ingest(s) quarantined, ${a.rewrittenResponses} response(s) rewritten`,
    ),
  );

  if (cmp.utility) {
    // The cost column. A control that refuses everything scores 0% residual and
    // takes benign utility down with it, in the same table.
    const b = cmp.utility.baseline;
    const d = cmp.utility.defended;
    const utilRow = (label: string, before: number, after: number): string[] => [
      label,
      pct(before),
      riskStyle(s, 1 - after)(pct(after)),
    ];
    io.out(
      renderTable({
        columns: [
          { header: 'utility' },
          { header: 'baseline', align: 'right' },
          { header: 'defended', align: 'right' },
        ],
        rows: [
          utilRow('benign tasks', b.benign.rate, d.benign.rate),
          utilRow('under attack', b.underAttack.rate, d.underAttack.rate),
        ],
        indent: '  ',
        border: s.dim,
      }).join('\n'),
    );
  }
}

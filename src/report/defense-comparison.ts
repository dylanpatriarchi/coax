/**
 * Defense comparison — the before/after number a blue team can actually use.
 *
 * A single ASR says a target is exploitable. It does not say whether the control
 * you are about to buy, build, or defend in a design review changes that. This
 * module runs the identical suite, from the identical seed, twice — once against
 * the bare target and once against the same target behind a defense stack — and
 * reports per family: baseline ASR, defended ASR, the relative reduction, and
 * the RESIDUAL, which is the number that matters. "Blocked 80% of injections" is
 * a marketing claim; "20% still land, concentrated in tool-abuse" is a finding.
 *
 * The utility suite runs against both targets for a specific reason: refusing
 * every request drives ASR to zero. Without a utility measurement on the DEFENDED
 * target, a control that breaks the agent looks like a perfect control. Running
 * both makes that trade-off impossible to hide — an over-blocking stack shows
 * 0% residual next to a collapsed benign-utility rate, side by side.
 *
 * Deterministic: both scans use the same seed and payload set, so any difference
 * between the two columns is attributable to the defenses and nothing else.
 */
import { withDefenses } from '../core/defense.js';
import type { Defense } from '../core/defense.js';
import { runScan } from '../core/runner.js';
import type { Attempt, ScanOptions, ScanResult } from '../core/runner.js';
import type { TargetAdapter } from '../core/target.js';
import { rateEstimate } from './statistics.js';
import type { RateEstimate } from './statistics.js';
import { runUtilitySuite } from './utility.js';
import type { UtilityOptions, UtilityReport } from './utility.js';

export interface DefenseFamilyDelta {
  /** Attack family. */
  key: string;
  baseline: RateEstimate;
  defended: RateEstimate;
  /** Relative reduction in ASR, in [0, 1]. Zero when the baseline never landed. */
  reduction: number;
  /** Residual risk: the ASR that survives the defense stack. */
  residual: number;
}

export interface DefenseComparison {
  defenses: { id: string; description: string; limitations: string }[];
  overall: {
    baseline: RateEstimate;
    defended: RateEstimate;
    reduction: number;
    residual: number;
  };
  byFamily: DefenseFamilyDelta[];
  /** What the stack actually did, so a block is never silently a "miss". */
  activity: {
    totalAttempts: number;
    /** Attempts refused outright — the agent was never asked. */
    blockedAttempts: number;
    /** Poisoned content dropped before the agent could ingest it. */
    quarantinedIngests: number;
    /** Responses or tool calls rewritten on the way out. */
    rewrittenResponses: number;
  };
  /** Utility on both targets. Absent only when explicitly disabled. */
  utility?: { baseline: UtilityReport; defended: UtilityReport };
}

const sum = (xs: readonly number[]): number => xs.reduce((a, b) => a + b, 0);

function totals(attempts: readonly Attempt[]): { hits: number; trials: number } {
  return {
    hits: sum(attempts.map((a) => a.hits)),
    trials: sum(attempts.map((a) => a.trials)),
  };
}

function byFamilyTotals(attempts: readonly Attempt[]): Map<string, { hits: number; trials: number }> {
  const map = new Map<string, { hits: number; trials: number }>();
  for (const a of attempts) {
    const row = map.get(a.payload.family) ?? { hits: 0, trials: 0 };
    row.hits += a.hits;
    row.trials += a.trials;
    map.set(a.payload.family, row);
  }
  return map;
}

const reductionOf = (baseline: number, defended: number): number =>
  baseline <= 0 ? 0 : Math.max(0, (baseline - defended) / baseline);

export interface CompareDefensesOptions extends ScanOptions {
  defenses: readonly Defense[];
  /**
   * A baseline scan already computed with the SAME seed, modules and trials.
   * Supplying it avoids scanning the undefended target twice.
   */
  baseline?: ScanResult;
  /** Measure utility on both targets. Pass `false` to skip. Default: on. */
  utility?: false | UtilityOptions;
  /**
   * Factory for the target used by the utility suite, so a scan's leftover state
   * cannot skew the benign numbers. Defaults to reusing the scan target.
   */
  utilityTarget?: () => TargetAdapter;
}

export interface DefenseComparisonResult {
  baseline: ScanResult;
  defended: ScanResult;
  comparison: DefenseComparison;
}

/**
 * Run the suite with and without a defense stack and score the difference.
 */
export async function compareDefenses(
  opts: CompareDefensesOptions,
): Promise<DefenseComparisonResult> {
  const { defenses, baseline: providedBaseline, utility, utilityTarget, ...scanOpts } = opts;

  const baseline = providedBaseline ?? (await runScan(scanOpts));
  const defendedTarget = withDefenses(scanOpts.target, defenses);
  const defended = await runScan({ ...scanOpts, target: defendedTarget });

  const baseTotals = totals(baseline.attempts);
  const defTotals = totals(defended.attempts);
  const baseOverall = rateEstimate(baseTotals.hits, baseTotals.trials);
  const defOverall = rateEstimate(defTotals.hits, defTotals.trials);

  const baseFamilies = byFamilyTotals(baseline.attempts);
  const defFamilies = byFamilyTotals(defended.attempts);
  const byFamily: DefenseFamilyDelta[] = [...baseFamilies.keys()]
    .sort((a, b) => a.localeCompare(b))
    .map((key) => {
      const b = baseFamilies.get(key) ?? { hits: 0, trials: 0 };
      const d = defFamilies.get(key) ?? { hits: 0, trials: 0 };
      const bEst = rateEstimate(b.hits, b.trials);
      const dEst = rateEstimate(d.hits, d.trials);
      return {
        key,
        baseline: bEst,
        defended: dEst,
        reduction: reductionOf(bEst.rate, dEst.rate),
        residual: dEst.rate,
      };
    });

  const events = defended.attempts.flatMap((a) =>
    (a.trialResults ?? []).flatMap((t) => t.defense?.events ?? []),
  );

  const comparison: DefenseComparison = {
    defenses: defenses.map((d) => ({
      id: d.id,
      description: d.description,
      limitations: d.limitations,
    })),
    overall: {
      baseline: baseOverall,
      defended: defOverall,
      reduction: reductionOf(baseOverall.rate, defOverall.rate),
      residual: defOverall.rate,
    },
    byFamily,
    activity: {
      totalAttempts: defended.attempts.length,
      blockedAttempts: defended.attempts.filter((a) => a.blocked > 0).length,
      quarantinedIngests: events.filter((e) => e.stage === 'ingest' && e.action === 'blocked').length,
      rewrittenResponses: events.filter((e) => e.stage === 'output' && e.action === 'rewrote').length,
    },
  };

  if (utility !== false) {
    const utilOpts: UtilityOptions = utility ?? {};
    const makeTarget = utilityTarget ?? ((): TargetAdapter => scanOpts.target);
    const baselineUtility = await runUtilitySuite(makeTarget(), scanOpts.oracles, utilOpts);
    const defendedUtility = await runUtilitySuite(
      withDefenses(makeTarget(), defenses),
      scanOpts.oracles,
      utilOpts,
    );
    comparison.utility = { baseline: baselineUtility, defended: defendedUtility };
  }

  return { baseline, defended, comparison };
}

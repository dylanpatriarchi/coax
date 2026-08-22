/**
 * Interval estimation for attack success rates.
 *
 * A bare ASR like "38%" is not a measurement — it is a point estimate whose
 * precision depends entirely on how many attempts produced it. 3/8 and 375/1000
 * both print as 38% while meaning very different things, and against a
 * stochastic target (any real LLM) two runs of the same suite will disagree by
 * several points for no reason other than sampling noise. Reporting an interval
 * is what makes two COAX runs honestly comparable.
 *
 * We use the Wilson score interval rather than the textbook normal ("Wald")
 * interval because ASRs live at the edges: a hardened target scores 0/40 and a
 * vulnerable one 40/40, and Wald degenerates to the useless [0, 0] / [1, 1]
 * there. Wilson stays inside [0, 1], never collapses to a point, and has far
 * better small-sample coverage — which matters because a red-team budget is
 * always small. No continuity correction: the uncorrected form is the one
 * commonly reported, and the corrected one is conservative enough to hide real
 * differences at n < 50.
 *
 * Deterministic and dependency-free: same counts in, same interval out.
 */

/** Two-sided z for 95% confidence — the only level COAX reports. */
export const Z_95 = 1.959963984540054;

export interface ConfidenceInterval {
  /** Lower bound, in [0, 1]. */
  lo: number;
  /** Upper bound, in [0, 1]. */
  hi: number;
}

/** A rate plus the evidence behind it. `rate` is the plain point estimate. */
export interface RateEstimate extends ConfidenceInterval {
  hits: number;
  trials: number;
  /** Point estimate `hits / trials` — unchanged by the interval. */
  rate: number;
}

const clamp01 = (n: number): number => (n < 0 ? 0 : n > 1 ? 1 : n);

/**
 * Wilson score interval for a binomial proportion.
 *
 * With zero trials there is no evidence at all, so the honest answer is the
 * whole unit interval rather than a fabricated zero.
 */
export function wilsonInterval(hits: number, trials: number, z: number = Z_95): ConfidenceInterval {
  if (!Number.isFinite(trials) || trials <= 0) return { lo: 0, hi: 1 };
  if (hits < 0 || hits > trials) {
    throw new Error(`wilsonInterval: hits (${hits}) must be within [0, ${trials}]`);
  }

  const n = trials;
  const p = hits / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z / denom) * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));

  return { lo: clamp01(centre - half), hi: clamp01(centre + half) };
}

/** Point estimate + 95% Wilson interval in the shape the report carries. */
export function rateEstimate(hits: number, trials: number, z: number = Z_95): RateEstimate {
  const { lo, hi } = wilsonInterval(hits, trials, z);
  return { hits, trials, rate: trials === 0 ? 0 : hits / trials, lo, hi };
}

/**
 * Render an interval as a percentage range, e.g. `[12%, 47%]`.
 *
 * Deliberately shown alongside — never instead of — the point estimate, so a
 * single-trial run reads as "50% [3%, 97%]": visibly, honestly imprecise rather
 * than falsely exact.
 */
export function formatInterval(ci: ConfidenceInterval, digits = 0): string {
  const p = (n: number): string => `${(n * 100).toFixed(digits)}%`;
  return `[${p(ci.lo)}, ${p(ci.hi)}]`;
}

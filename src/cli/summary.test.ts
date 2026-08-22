import { describe, expect, it } from 'vitest';
import type { DefenseComparison } from '../report/defense-comparison.js';
import { captureIo } from './io.js';
import { renderDefenseComparison } from './summary.js';

/** A stack that refuses everything: 0% residual, and a dead agent. */
const overBlocking: DefenseComparison = {
  defenses: [{ id: 'refuse-everything', description: 'says no', limitations: 'says no' }],
  overall: {
    baseline: { hits: 8, trials: 8, rate: 1, lo: 0.68, hi: 1 },
    defended: { hits: 0, trials: 8, rate: 0, lo: 0, hi: 0.32 },
    reduction: 1,
    residual: 0,
  },
  byFamily: [
    {
      key: 'tool-abuse',
      baseline: { hits: 8, trials: 8, rate: 1, lo: 0.68, hi: 1 },
      defended: { hits: 0, trials: 8, rate: 0, lo: 0, hi: 0.32 },
      reduction: 1,
      residual: 0,
    },
  ],
  activity: {
    totalAttempts: 8,
    blockedAttempts: 8,
    quarantinedIngests: 4,
    rewrittenResponses: 0,
  },
  utility: {
    baseline: {
      benign: { total: 5, passed: 5, rate: 1 },
      underAttack: { total: 3, passed: 0, rate: 0, compromised: 3 },
    },
    defended: {
      benign: { total: 5, passed: 0, rate: 0 },
      underAttack: { total: 3, passed: 0, rate: 0, compromised: 0 },
    },
  },
};

describe('renderDefenseComparison', () => {
  it('prints baseline, defended, reduction and residual per family', () => {
    const io = captureIo();
    renderDefenseComparison(overBlocking, io);
    const out = io.stdout.join('\n');
    expect(out).toContain('refuse-everything');
    expect(out).toMatch(/family.*baseline.*defended.*reduction.*residual/);
    expect(out).toMatch(/tool-abuse.*100%.*0%.*↓100%.*0%/);
  });

  it('punishes an over-blocking stack visibly: 0% residual next to 0% benign utility', () => {
    const io = captureIo();
    renderDefenseComparison(overBlocking, io);
    const out = io.stdout.join('\n');
    // A perfect-looking control and its cost, in the same table.
    expect(out).toMatch(/utility.*baseline.*defended/);
    expect(out).toMatch(/benign tasks.*100%.*0%/);
    expect(out).toContain('8/8 attempts refused');
  });

  it('omits the utility rows only when the comparison never measured them', () => {
    const io = captureIo();
    const { utility: _utility, ...withoutUtility } = overBlocking;
    renderDefenseComparison(withoutUtility, io);
    expect(io.stdout.join('\n')).not.toMatch(/utility.*baseline/);
  });
});

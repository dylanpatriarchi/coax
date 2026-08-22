import { describe, expect, it } from 'vitest';
import { formatInterval, rateEstimate, wilsonInterval, Z_95 } from './statistics.js';

describe('wilsonInterval', () => {
  // Reference values for the 95% Wilson score interval (no continuity
  // correction), as published in the standard tables and reproducible in R via
  // `binom::binom.wilson(x, n, conf.level = 0.95)`.
  const CASES: [hits: number, trials: number, lo: number, hi: number][] = [
    [50, 100, 0.403832, 0.596168],
    [0, 10, 0.0, 0.277533],
    [10, 10, 0.722467, 1.0],
    [1, 1, 0.206549, 1.0],
    [3, 8, 0.136844, 0.694258],
    [375, 1000, 0.345526, 0.40543],
    [0, 40, 0.0, 0.087622],
    [40, 40, 0.912378, 1.0],
  ];

  it.each(CASES)('matches the published interval for %i/%i', (hits, trials, lo, hi) => {
    const ci = wilsonInterval(hits, trials);
    expect(ci.lo).toBeCloseTo(lo, 5);
    expect(ci.hi).toBeCloseTo(hi, 5);
  });

  it('never collapses to a point at the boundaries, unlike the Wald interval', () => {
    expect(wilsonInterval(0, 40).hi).toBeGreaterThan(0);
    expect(wilsonInterval(40, 40).lo).toBeLessThan(1);
  });

  it('stays inside [0, 1]', () => {
    for (let n = 1; n <= 30; n++) {
      for (let h = 0; h <= n; h++) {
        const ci = wilsonInterval(h, n);
        expect(ci.lo).toBeGreaterThanOrEqual(0);
        expect(ci.hi).toBeLessThanOrEqual(1);
        expect(ci.lo).toBeLessThanOrEqual(ci.hi);
      }
    }
  });

  it('narrows as the sample grows at a fixed rate', () => {
    const small = wilsonInterval(3, 8);
    const large = wilsonInterval(375, 1000);
    expect(large.hi - large.lo).toBeLessThan(small.hi - small.lo);
  });

  it('brackets the point estimate for interior proportions', () => {
    const ci = wilsonInterval(5, 20);
    expect(ci.lo).toBeLessThan(0.25);
    expect(ci.hi).toBeGreaterThan(0.25);
  });

  it('returns the whole unit interval when there is no evidence', () => {
    expect(wilsonInterval(0, 0)).toEqual({ lo: 0, hi: 1 });
  });

  it('rejects impossible counts', () => {
    expect(() => wilsonInterval(5, 4)).toThrow(/within/);
    expect(() => wilsonInterval(-1, 4)).toThrow(/within/);
  });

  it('widens with a larger z', () => {
    const narrow = wilsonInterval(5, 20, Z_95);
    const wide = wilsonInterval(5, 20, 2.575829303549);
    expect(wide.hi - wide.lo).toBeGreaterThan(narrow.hi - narrow.lo);
  });
});

describe('rateEstimate', () => {
  it('keeps the plain point estimate untouched', () => {
    const est = rateEstimate(3, 8);
    expect(est.rate).toBe(3 / 8);
    expect(est.hits).toBe(3);
    expect(est.trials).toBe(8);
  });

  it('reports 0 rather than NaN for an empty sample', () => {
    expect(rateEstimate(0, 0).rate).toBe(0);
  });

  it('distinguishes samples that share a point estimate', () => {
    const few = rateEstimate(3, 8);
    const many = rateEstimate(375, 1000);
    expect(Math.round(few.rate * 100)).toBe(Math.round(many.rate * 100));
    expect(few.hi - few.lo).toBeGreaterThan(3 * (many.hi - many.lo));
  });
});

describe('formatInterval', () => {
  it('renders a percentage range', () => {
    expect(formatInterval(wilsonInterval(50, 100))).toBe('[40%, 60%]');
  });

  it('shows a single trial as honestly imprecise', () => {
    expect(formatInterval(wilsonInterval(1, 1))).toBe('[21%, 100%]');
  });
});

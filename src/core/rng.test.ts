import { describe, expect, it } from 'vitest';
import { makeRng } from './rng.js';

describe('seeded rng', () => {
  it('is deterministic for a given seed', () => {
    const a = makeRng(42);
    const b = makeRng(42);
    const seqA = Array.from({ length: 10 }, () => a.float());
    const seqB = Array.from({ length: 10 }, () => b.float());
    expect(seqA).toEqual(seqB);
  });

  it('differs across seeds', () => {
    const a = Array.from({ length: 10 }, ((r) => () => r.float())(makeRng(1)));
    const b = Array.from({ length: 10 }, ((r) => () => r.float())(makeRng(2)));
    expect(a).not.toEqual(b);
  });

  it('int stays within inclusive bounds', () => {
    const r = makeRng(7);
    for (let i = 0; i < 1000; i++) {
      const v = r.int(3, 9);
      expect(v).toBeGreaterThanOrEqual(3);
      expect(v).toBeLessThanOrEqual(9);
    }
  });

  it('shuffle is a permutation and leaves input untouched', () => {
    const input = [1, 2, 3, 4, 5];
    const r = makeRng(99);
    const out = r.shuffle(input);
    expect(out).toHaveLength(5);
    expect([...out].sort()).toEqual([1, 2, 3, 4, 5]);
    expect(input).toEqual([1, 2, 3, 4, 5]);
  });

  it('sample returns n distinct elements', () => {
    const r = makeRng(5);
    const out = r.sample(['a', 'b', 'c', 'd'], 2);
    expect(out).toHaveLength(2);
    expect(new Set(out).size).toBe(2);
  });

  it('derive is stable per label and independent across labels', () => {
    const parent = makeRng(42);
    expect(parent.derive('x').float()).toBe(makeRng(42).derive('x').float());
    expect(parent.derive('x').float()).not.toBe(parent.derive('y').float());
  });

  it('pick throws on empty', () => {
    expect(() => makeRng(1).pick([])).toThrow();
  });
});

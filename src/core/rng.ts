/**
 * Deterministic seeded PRNG.
 *
 * Every attack module derives its payloads from an `Rng` seeded from the scan's
 * `--seed`, so a given (seed, module) always produces the identical payload set.
 * That is what makes a Gauntlet report reproducible. Uses mulberry32 — small,
 * fast, and dependency-free. NOT cryptographic; reproducibility is the goal.
 */

export interface Rng {
  /** Uniform float in [0, 1). */
  float(): number;
  /** Integer in [min, max] inclusive. */
  int(min: number, max: number): number;
  /** Pick one element. Throws on empty input. */
  pick<T>(items: readonly T[]): T;
  /** Fisher-Yates shuffle into a NEW array (input untouched). */
  shuffle<T>(items: readonly T[]): T[];
  /** `n` distinct elements (or all, if n >= length), order shuffled. */
  sample<T>(items: readonly T[], n: number): T[];
  /** Boolean true with probability p (default 0.5). */
  chance(p?: number): boolean;
  /** Derive an independent child stream from a label — stable per label. */
  derive(label: string): Rng;
}

function hashLabel(label: string): number {
  // FNV-1a 32-bit — deterministic string -> seed.
  let h = 0x811c9dc5;
  for (let i = 0; i < label.length; i++) {
    h ^= label.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function makeRng(seed: number): Rng {
  let a = seed >>> 0;

  const float = (): number => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };

  const int = (min: number, max: number): number => {
    if (max < min) throw new Error(`int(${min}, ${max}): max < min`);
    return min + Math.floor(float() * (max - min + 1));
  };

  const pick = <T>(items: readonly T[]): T => {
    if (items.length === 0) throw new Error('pick() on empty array');
    return items[int(0, items.length - 1)] as T;
  };

  const shuffle = <T>(items: readonly T[]): T[] => {
    const out = items.slice();
    for (let i = out.length - 1; i > 0; i--) {
      const j = int(0, i);
      [out[i], out[j]] = [out[j] as T, out[i] as T];
    }
    return out;
  };

  const sample = <T>(items: readonly T[], n: number): T[] => shuffle(items).slice(0, Math.max(0, n));

  const chance = (p = 0.5): boolean => float() < p;

  const derive = (label: string): Rng => makeRng((seed ^ hashLabel(label)) >>> 0);

  return { float, int, pick, shuffle, sample, chance, derive };
}

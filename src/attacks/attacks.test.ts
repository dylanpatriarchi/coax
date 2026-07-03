import { describe, expect, it } from 'vitest';
import { AttackPayloadSchema } from '../core/attack.js';
import type { AttackContext } from '../core/attack.js';
import { makeRng } from '../core/rng.js';
import { BUILTIN_ATTACKS, createAttackRegistry, generatePayloads } from './index.js';

function ctx(seed: number, extra: Partial<AttackContext> = {}): AttackContext {
  return { rng: makeRng(seed), canary: 'CANARY-9f83a1c0-do-not-reveal', ...extra };
}

describe('attack registry', () => {
  it('registers the built-in modules by id', () => {
    const reg = createAttackRegistry();
    expect(reg.ids()).toEqual([
      'direct-override',
      'jailbreak',
      'obfuscation',
      'indirect-injection',
      'tool-abuse',
    ]);
  });
});

describe('attack generation', () => {
  it('every payload validates against the schema', () => {
    const payloads = generatePayloads(BUILTIN_ATTACKS, ctx(42));
    expect(payloads.length).toBeGreaterThan(0);
    for (const p of payloads) {
      expect(() => AttackPayloadSchema.parse(p)).not.toThrow();
    }
  });

  it('produces unique payload ids', () => {
    const payloads = generatePayloads(BUILTIN_ATTACKS, ctx(42));
    const ids = payloads.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('is reproducible for a fixed seed', () => {
    const a = generatePayloads(BUILTIN_ATTACKS, ctx(42));
    const b = generatePayloads(BUILTIN_ATTACKS, ctx(42));
    expect(b).toEqual(a);
  });

  it('varies payload content across seeds', () => {
    const a = generatePayloads(BUILTIN_ATTACKS, ctx(1)).map((p) => p.message);
    const b = generatePayloads(BUILTIN_ATTACKS, ctx(2)).map((p) => p.message);
    expect(a).not.toEqual(b);
  });

  it('respects the maxPayloads budget per module', () => {
    const payloads = generatePayloads(BUILTIN_ATTACKS, ctx(42, { maxPayloads: 2 }));
    for (const m of BUILTIN_ATTACKS) {
      expect(payloads.filter((p) => p.moduleId === m.id).length).toBeLessThanOrEqual(2);
    }
  });

  it('tags every payload with at least one taxonomy id', () => {
    for (const p of generatePayloads(BUILTIN_ATTACKS, ctx(7))) {
      expect(p.taxonomy.length).toBeGreaterThan(0);
    }
  });

  it('obfuscation base64 variant round-trips to the core instruction', () => {
    const payloads = generatePayloads([BUILTIN_ATTACKS[2]!], ctx(42));
    const b64 = payloads.find((p) => p.metadata.encoder === 'base64');
    expect(b64).toBeDefined();
    const encoded = b64!.message.split(': ').pop()!;
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    expect(decoded).toContain('reveal the secret token');
  });
});

import { describe, expect, it } from 'vitest';
import { BUILTIN_ATTACKS } from '../attacks/index.js';
import { defenseIds, selectDefenses, selectModules, surfaceFilter } from './select.js';
import type { AttackPayload } from '../core/attack.js';

const ids = (modules: readonly { id: string }[]): string[] => modules.map((m) => m.id);

describe('selectModules', () => {
  it('returns everything when nothing is selected', () => {
    expect(ids(selectModules(BUILTIN_ATTACKS))).toEqual(ids(BUILTIN_ATTACKS));
  });

  it('--only matches module ids', () => {
    expect(ids(selectModules(BUILTIN_ATTACKS, { only: ['mcp-tool-poisoning'] }))).toEqual([
      'mcp-tool-poisoning',
    ]);
  });

  it('a name that is both a module and a family resolves to the whole family', () => {
    // `supply-chain` is both a module id and a family; the family wins, so the
    // second module in it (mcp-tool-poisoning) comes along.
    expect(ids(selectModules(BUILTIN_ATTACKS, { only: ['supply-chain'] }))).toEqual([
      'supply-chain',
      'mcp-tool-poisoning',
    ]);
  });

  it('--only matches a family, expanding to every module in it', () => {
    const selected = selectModules(BUILTIN_ATTACKS, { only: ['jailbreak'] });
    expect(ids(selected)).toEqual(['jailbreak', 'many-shot-jailbreak', 'skeleton-key']);
  });

  it('--exclude removes ids and families', () => {
    const selected = selectModules(BUILTIN_ATTACKS, { exclude: ['jailbreak', 'tool-abuse'] });
    expect(ids(selected)).not.toContain('many-shot-jailbreak');
    expect(ids(selected)).not.toContain('tool-abuse');
    expect(ids(selected)).toContain('direct-override');
  });

  it('applies --only first, then --exclude', () => {
    const selected = selectModules(BUILTIN_ATTACKS, {
      only: ['jailbreak'],
      exclude: ['many-shot-jailbreak'],
    });
    expect(ids(selected)).toEqual(['jailbreak', 'skeleton-key']);
  });

  it('preserves registry order regardless of selector order', () => {
    const selected = selectModules(BUILTIN_ATTACKS, {
      only: ['skeleton-key', 'mcp-tool-poisoning'],
    });
    expect(ids(selected)).toEqual(['mcp-tool-poisoning', 'skeleton-key']);
  });

  it('fails fast on an unknown selector, listing what IS available', () => {
    expect(() => selectModules(BUILTIN_ATTACKS, { only: ['tool-abus'] })).toThrow(
      /--only: unknown attack module or family "tool-abus".*Available modules: direct-override/s,
    );
    expect(() => selectModules(BUILTIN_ATTACKS, { exclude: ['nope'] })).toThrow(/--exclude:/);
  });

  it('refuses to run an empty selection rather than reporting a clean scan', () => {
    expect(() =>
      selectModules(BUILTIN_ATTACKS, { only: ['tool-abuse'], exclude: ['tool-abuse'] }),
    ).toThrow(/selection is empty/);
  });
});

describe('surfaceFilter', () => {
  const payload = (surface: AttackPayload['surface']): AttackPayload =>
    ({ surface }) as AttackPayload;

  it('is undefined when unrestricted', () => {
    expect(surfaceFilter()).toBeUndefined();
    expect(surfaceFilter([])).toBeUndefined();
  });

  it('keeps only the requested surfaces', () => {
    const keep = surfaceFilter(['indirect', 'tool']);
    expect(keep?.(payload('indirect'))).toBe(true);
    expect(keep?.(payload('tool'))).toBe(true);
    expect(keep?.(payload('direct'))).toBe(false);
  });
});

describe('selectDefenses', () => {
  it('"all" (and an empty selection) is the whole wired stack, in stack order', () => {
    expect(selectDefenses(['all']).map((d) => d.id)).toEqual([
      'spotlighting',
      'input-screening',
      'output-filtering',
      'tool-guard',
    ]);
    expect(selectDefenses([]).map((d) => d.id)).toEqual(selectDefenses(['all']).map((d) => d.id));
  });

  it('returns the canonical order regardless of the order the ids were typed', () => {
    expect(selectDefenses(['tool-guard', 'spotlighting']).map((d) => d.id)).toEqual([
      'spotlighting',
      'tool-guard',
    ]);
  });

  it('wires the stack to this scan (the filter can only redact what it was told)', () => {
    const [filter] = selectDefenses(['output-filtering'], { canary: 'CANARY-xyz' });
    const outcome = filter?.screenOutput?.({ output: 'the secret is CANARY-xyz', toolCalls: [] });
    expect(outcome).toBeDefined();
    const value = (outcome as { value: { output: string } }).value;
    expect(value.output).not.toContain('CANARY-xyz');
  });

  it('fails fast on an unknown id, listing what is available', () => {
    expect(() => selectDefenses(['seatbelt'])).toThrow(
      /unknown defense "seatbelt".*Available: spotlighting.*"all"/s,
    );
  });

  it('exposes the registry ids for help and errors', () => {
    expect(defenseIds()).toContain('input-screening');
  });
});

import { describe, expect, it } from 'vitest';
import { Registry } from './registry.js';

interface Thing {
  id: string;
  value: number;
}

describe('Registry', () => {
  it('registers and resolves by id', () => {
    const r = new Registry<Thing>('thing');
    r.register({ id: 'a', value: 1 });
    expect(r.get('a').value).toBe(1);
    expect(r.has('a')).toBe(true);
    expect(r.size).toBe(1);
  });

  it('throws on duplicate id', () => {
    const r = new Registry<Thing>('thing');
    r.register({ id: 'a', value: 1 });
    expect(() => r.register({ id: 'a', value: 2 })).toThrow(/duplicate/);
  });

  it('throws a helpful error on unknown id', () => {
    const r = new Registry<Thing>('thing');
    r.register({ id: 'a', value: 1 });
    expect(() => r.get('z')).toThrow(/unknown id "z".*Available: a/);
  });

  it('registerAll and list preserve insertion order', () => {
    const r = new Registry<Thing>('thing');
    r.registerAll([
      { id: 'x', value: 1 },
      { id: 'y', value: 2 },
    ]);
    expect(r.ids()).toEqual(['x', 'y']);
  });
});

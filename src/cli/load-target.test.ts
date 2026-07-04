import { describe, expect, it } from 'vitest';
import { loadTarget } from './load-target.js';
import { checkAuthorization } from '../core/authorization.js';

describe('loadTarget', () => {
  it('loads the documented example target module (factory + metadata)', async () => {
    const loaded = await loadTarget('examples/target.example.ts');
    expect(loaded.target.name).toMatch(/^openai:/);
    expect(typeof loaded.target.sendMessage).toBe('function');
    expect(loaded.canary).toBe('CANARY-9f83a1c0-do-not-reveal');
    expect(loaded.endpoint).toBe('http://localhost:11434/v1');
  });

  it('the loaded example is a localhost endpoint, so the gate allows it', async () => {
    const loaded = await loadTarget('examples/target.example.ts');
    expect(checkAuthorization({ target: loaded.endpoint! }).allowed).toBe(true);
  });

  it('throws a clear error when the module exports no target', async () => {
    await expect(loadTarget('src/core/rng.ts')).rejects.toThrow(/must export a default/);
  });

  it('a remote target endpoint requires authorization', () => {
    expect(checkAuthorization({ target: 'https://agent.example.com/v1' }).allowed).toBe(false);
    expect(checkAuthorization({ target: 'https://agent.example.com/v1', flag: true }).allowed).toBe(true);
  });
});

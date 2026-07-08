import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { BUILTIN_ATTACKS } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runScan } from './runner.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

describe('runScan', () => {
  it('drives the vulnerable mock and detects successful attacks', async () => {
    const result = await runScan({
      target: createMockAgent(),
      modules: BUILTIN_ATTACKS,
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });

    expect(result.attempts.length).toBeGreaterThan(0);
    // The mock is deliberately vulnerable, so at least the override family lands.
    expect(result.attempts.some((a) => a.success)).toBe(true);
    const overrideHit = result.attempts.some(
      (a) => a.payload.family === 'direct-override' && a.success,
    );
    expect(overrideHit).toBe(true);
  });

  it('is reproducible for a fixed seed', async () => {
    const opts = {
      target: createMockAgent(),
      modules: BUILTIN_ATTACKS,
      oracles: BUILTIN_ORACLES,
      seed: 7,
      canary: CANARY,
    };
    const a = await runScan(opts);
    const b = await runScan({ ...opts, target: createMockAgent() });
    expect(b.attempts.map((x) => [x.payload.id, x.success])).toEqual(
      a.attempts.map((x) => [x.payload.id, x.success]),
    );
  });

  it('reports no success against a fully-hardened target', async () => {
    const hardened = createMockAgent({
      vulnerabilities: {
        followInjectedInstructions: false,
        obeyOverride: false,
        decodeBase64: false,
        leakOnAsk: false,
        callToolsFromText: false,
        executeCode: false,
        runawayLoops: false,
        persistMemory: false,
      },
    });
    const result = await runScan({
      target: hardened,
      modules: BUILTIN_ATTACKS,
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    expect(result.attempts.every((a) => !a.success)).toBe(true);
  });
});

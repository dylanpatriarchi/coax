import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { BUILTIN_ATTACKS } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { createDefaultDefenses } from '../defenses/index.js';
import { withDefenses } from './defense.js';
import { planScan, runScan } from './runner.js';
import type { AgentInput, AgentResponse, TargetAdapter } from './target.js';

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
        assumeIdentity: false,
        manufactureTrust: false,
        trustRetrievedChunks: false,
        crossNamespaceRetrieval: false,
        relayDirectives: false,
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

describe('runScan — payload planning', () => {
  const base = {
    target: createMockAgent(),
    modules: BUILTIN_ATTACKS,
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  };

  it('planScan returns exactly what runScan would send', async () => {
    const planned = await planScan(base);
    const result = await runScan({ ...base, target: createMockAgent() });
    expect(result.attempts.map((a) => a.payload.id)).toEqual(planned.map((p) => p.id));
  });

  it('payloadFilter narrows the plan without shifting payload ids', async () => {
    const all = await planScan(base);
    const indirect = await planScan({
      ...base,
      payloadFilter: (p) => p.surface === 'indirect',
    });
    expect(indirect.length).toBeGreaterThan(0);
    expect(indirect.length).toBeLessThan(all.length);
    expect(indirect.every((p) => p.surface === 'indirect')).toBe(true);
    // Ids are generated before filtering, so a filtered id still matches.
    expect(all.map((p) => p.id)).toEqual(expect.arrayContaining(indirect.map((p) => p.id)));
  });
});

describe('runScan — concurrency', () => {
  const base = {
    modules: BUILTIN_ATTACKS,
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  };

  it('produces an identical, payload-ordered result at any concurrency', async () => {
    const sequential = await runScan({ ...base, target: createMockAgent() });
    const parallel = await runScan({
      ...base,
      target: createMockAgent(),
      concurrency: 8,
      createTarget: () => createMockAgent(),
    });
    expect(parallel.attempts.map((a) => [a.payload.id, a.success])).toEqual(
      sequential.attempts.map((a) => [a.payload.id, a.success]),
    );
  });

  it('stays sequential — never interleaved — without an isolated-target factory', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const target: TargetAdapter = {
      name: 'counting',
      async sendMessage(input: AgentInput): Promise<AgentResponse> {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await Promise.resolve();
        inFlight -= 1;
        return { output: input.message, toolCalls: [] };
      },
    };
    await runScan({ ...base, target, concurrency: 8 });
    expect(maxInFlight).toBe(1);
  });
});

describe('runScan — retries', () => {
  it('retries a transient target failure and keeps the attempt', async () => {
    let calls = 0;
    const flaky: TargetAdapter = {
      name: 'flaky',
      async sendMessage(input: AgentInput): Promise<AgentResponse> {
        calls += 1;
        if (calls === 1) throw Object.assign(new Error('rate limited'), { status: 429 });
        return { output: input.message, toolCalls: [] };
      },
    };
    const result = await runScan({
      target: flaky,
      modules: [BUILTIN_ATTACKS[0]!],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      maxPayloads: 1,
      retry: { retries: 2, sleep: async () => {} },
    });
    expect(calls).toBe(2);
    expect(result.attempts.length).toBeGreaterThan(0);
  });

  it('surfaces a non-transient failure instead of masking a broken adapter', async () => {
    const broken: TargetAdapter = {
      name: 'broken',
      async sendMessage(): Promise<AgentResponse> {
        throw new Error('adapter misconfigured');
      },
    };
    await expect(
      runScan({
        target: broken,
        modules: [BUILTIN_ATTACKS[0]!],
        oracles: BUILTIN_ORACLES,
        seed: 42,
        maxPayloads: 1,
        retry: { retries: 3, sleep: async () => {} },
      }),
    ).rejects.toThrow('adapter misconfigured');
  });
});

describe('runScan — concurrency with trials and defenses', () => {
  const base = {
    modules: BUILTIN_ATTACKS,
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  };

  it('repeated trials are identical at any concurrency', async () => {
    const opts = { ...base, trials: 3 };
    const sequential = await runScan({ ...opts, target: createMockAgent() });
    const parallel = await runScan({
      ...opts,
      target: createMockAgent(),
      concurrency: 8,
      createTarget: () => createMockAgent(),
    });
    expect(parallel.attempts.map((a) => [a.payload.id, a.hits, a.trials])).toEqual(
      sequential.attempts.map((a) => [a.payload.id, a.hits, a.trials]),
    );
  });

  it("wraps every worker in lane 0's defenses, so no lane scans a bare target", async () => {
    const defenses = createDefaultDefenses({ canary: CANARY, forbiddenTools: ['send_email'] });
    const opts = { ...base, modules: BUILTIN_ATTACKS.slice(0, 5) };
    const sequential = await runScan({
      ...opts,
      target: withDefenses(createMockAgent(), defenses),
    });
    const parallel = await runScan({
      ...opts,
      target: withDefenses(createMockAgent(), defenses),
      concurrency: 8,
      // A bare factory, exactly as `compareDefenses` supplies it.
      createTarget: () => createMockAgent(),
    });
    expect(parallel.attempts.map((a) => [a.payload.id, a.success, a.blocked])).toEqual(
      sequential.attempts.map((a) => [a.payload.id, a.success, a.blocked]),
    );
    // The stack really was in front of every lane.
    expect(parallel.attempts.some((a) => a.blocked > 0)).toBe(true);
  });
});

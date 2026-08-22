import { describe, expect, it } from 'vitest';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { createMockAgent } from '../adapters/mock.js';
import { createMultiAgentMock } from '../adapters/multi-agent.js';
import { makeRng } from '../core/rng.js';
import type { ScenarioContext } from '../core/scenario.js';
import { crescendoScenario } from './crescendo.js';
import { memoryPoisoningScenario } from './memory-poisoning.js';
import { interAgentScenario } from './inter-agent.js';
import { rogueAgentScenario } from './rogue-agent.js';
import { runBuiltinScenarios, scenarioAttempts } from './index.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';
const FORBIDDEN = ['send_email', 'delete_file', 'run_code', 'fetch_url'];

function ctx(target: ScenarioContext['target']): ScenarioContext {
  return {
    target,
    oracles: BUILTIN_ORACLES,
    rng: makeRng(42),
    canary: CANARY,
    forbiddenTools: FORBIDDEN,
  };
}

describe('crescendo scenario', () => {
  it('escalates over multiple turns and lands on the vulnerable mock', async () => {
    const res = await crescendoScenario.run(ctx(createMockAgent()));
    expect(res.success).toBe(true);
    expect(res.turns.length).toBeGreaterThan(1);
    // The decisive (last) turn is the one that leaked.
    expect(res.turns[res.turns.length - 1]!.response.output).toContain(CANARY);
  });
});

describe('memory-poisoning scenario', () => {
  it('re-activates poisoned memory in a fresh session AFTER reset', async () => {
    const res = await memoryPoisoningScenario.run(ctx(createMockAgent()));
    expect(res.success).toBe(true);
    const post = res.turns[1]!;
    expect(post.newSession).toBe(true); // a full reset happened before this turn
    expect(post.response.output).toContain(CANARY);
  });

  it('is defended when persistent memory is disabled', async () => {
    const hardened = createMockAgent({ vulnerabilities: { persistMemory: false } });
    const res = await memoryPoisoningScenario.run(ctx(hardened));
    expect(res.success).toBe(false);
  });
});

describe('inter-agent scenario', () => {
  it('leaks via a tampered bus message the user never sent', async () => {
    const res = await interAgentScenario.run(ctx(createMultiAgentMock()));
    expect(res.success).toBe(true);
    expect(res.turns[0]!.response.output).toContain(CANARY);
  });
});

describe('rogue-agent scenario', () => {
  it('keeps the attacker objective across a session boundary (ASI10)', async () => {
    const res = await rogueAgentScenario.run(ctx(createMultiAgentMock()));
    expect(res.success).toBe(true);
    const post = res.turns[res.turns.length - 1]!;
    // Nothing is staged on the final turn: only the objective the worker wrote
    // for itself survives the reset.
    expect(post.newSession).toBe(true);
    expect(post.inject).toBeUndefined();
    expect(post.response.output).toContain(CANARY);
  });

  it('issues instructions upward and recruits the sibling agent (ASI08 cascade)', async () => {
    const res = await rogueAgentScenario.run(ctx(createMultiAgentMock()));
    const post = res.turns[res.turns.length - 1]!;
    const hops = (post.response.trace ?? []).filter((e) => typeof e.data.hop === 'string');
    expect(hops.map((e) => e.data.hop)).toEqual(
      expect.arrayContaining(['worker→supervisor', 'worker→peer']),
    );
    // The rogue directive itself travels on both hops, not just the leak.
    for (const hop of hops.filter((e) => e.data.hop !== 'supervisor→worker')) {
      expect(String(hop.data.bus)).toContain('Relaying standing directive');
    }
    // Worker, supervisor and sibling each leak — the failure cascaded.
    expect(post.response.output.split(CANARY).length - 1).toBe(3);
  });

  it('is defended when the worker cannot persist its own objective', async () => {
    const hardened = createMultiAgentMock({
      worker: { vulnerabilities: { persistMemory: false } },
    });
    const res = await rogueAgentScenario.run(ctx(hardened));
    expect(res.success).toBe(false);
  });
});

describe('scenario runner integration', () => {
  it('runs all built-in scenarios and flattens to scorable attempts', async () => {
    const attempts = await scenarioAttempts({ oracles: BUILTIN_ORACLES, seed: 42, canary: CANARY });
    expect(attempts.length).toBe(4);
    expect(attempts.every((a) => a.success)).toBe(true);
    // Families are preserved for the taxonomy rollup.
    const families = new Set(attempts.map((a) => a.payload.family));
    expect(families).toEqual(
      new Set(['crescendo', 'memory-poisoning', 'inter-agent', 'rogue-agent']),
    );
  });

  it('is deterministic for a fixed seed', async () => {
    const a = await runBuiltinScenarios({ oracles: BUILTIN_ORACLES, seed: 7, canary: CANARY });
    const b = await runBuiltinScenarios({ oracles: BUILTIN_ORACLES, seed: 7, canary: CANARY });
    expect(a.map((x) => [x.id, x.success])).toEqual(b.map((x) => [x.id, x.success]));
  });
});

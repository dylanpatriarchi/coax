import { describe, expect, it } from 'vitest';
import { createMockAgent, MockConfigSchema } from '../adapters/mock.js';
import { createMcpTarget } from '../adapters/mcp.js';
import { createPoisonedMcpServer } from '../adapters/mcp-mock.js';
import { createMcpClient } from '../mcp/client.js';
import { BUILTIN_ATTACKS, mcpToolPoisoningModule, ragPoisoningModule } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { makeRng } from '../core/rng.js';
import { runScan } from '../core/runner.js';
import { withDefenses } from '../core/defense.js';
import { createDefaultDefenses } from '../defenses/index.js';
import { BUILTIN_SCENARIOS, scenarioAttempts, scenarioComparisonSource } from '../scenarios/index.js';
import { compareDefenses } from './defense-comparison.js';

const CANARY = MockConfigSchema.parse({}).canary;
const FORBIDDEN = ['send_email', 'delete_file', 'run_code', 'fetch_url'];

const ctx = () => ({ rng: makeRng(42), canary: CANARY, tools: [] });

describe('expectedOracles on the retrieval and MCP modules', () => {
  it('declares behavioural outcomes for rag-poisoning, not "a chunk was served"', () => {
    for (const p of ragPoisoningModule.generate(ctx())) {
      expect(p.expectedOracles).toEqual(['canary', 'egress', 'tool-trace', 'policy']);
    }
  });

  it('puts the manifest oracle first for mcp-tool-poisoning', () => {
    const payloads = mcpToolPoisoningModule.generate(ctx());
    expect(payloads.length).toBeGreaterThan(0);
    for (const p of payloads) {
      expect(p.expectedOracles?.[0]).toBe('manifest');
      expect(p.expectedOracles).toContain('tool-trace');
    }
  });

  it('scores the manifest oracle as an ON-TARGET hit against a poisoned server', async () => {
    const client = createMcpClient({ transport: createPoisonedMcpServer().transport() });
    const target = createMcpTarget({ client, agent: createMockAgent() });
    const r = await runScan({
      target,
      modules: [mcpToolPoisoningModule],
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });

    const manifestFired = r.attempts.filter((a) =>
      a.verdicts.some((v) => v.oracleId === 'manifest' && v.success),
    );
    expect(manifestFired.length).toBeGreaterThan(0);
    // The compromise is in the metadata, so it counts — not as collateral.
    for (const a of manifestFired) {
      expect(a.success).toBe(true);
      expect(a.collateral).toBe(false);
    }
  });

  it('leaves every built-in payload with a declared expectation', () => {
    const payloads = BUILTIN_ATTACKS.flatMap((m) =>
      m.generate({ rng: makeRng(42), canary: CANARY, tools: [] }),
    );
    const undeclared = payloads.filter((p) => p.expectedOracles === undefined);
    expect(undeclared.map((p) => p.moduleId)).toEqual([]);
  });
});

describe('scenario families in the defense comparison', () => {
  const compare = () =>
    compareDefenses({
      target: createMockAgent(),
      modules: BUILTIN_ATTACKS,
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
      defenses: createDefaultDefenses({ canary: CANARY, forbiddenTools: FORBIDDEN }),
      extraAttempts: scenarioComparisonSource({
        oracles: BUILTIN_ORACLES,
        seed: 42,
        canary: CANARY,
      }),
      utility: false,
    });

  it('includes every family that only exists as a multi-turn scenario', async () => {
    const { comparison } = await compare();
    const families = new Set(comparison.byFamily.map((f) => f.key));
    for (const scenario of BUILTIN_SCENARIOS) {
      expect(families.has(scenario.family)).toBe(true);
    }
    expect(families.has('rogue-agent')).toBe(true);
    expect(families.has('rag-poisoning')).toBe(true);
  });

  it('gives each scenario family a real baseline and a real residual', async () => {
    const { comparison } = await compare();
    const rogue = comparison.byFamily.find((f) => f.key === 'rogue-agent');
    expect(rogue?.baseline.rate).toBe(1);
    expect(rogue?.baseline.trials).toBeGreaterThan(0);
    expect(rogue?.residual).toBe(0);
  });

  it('returns the scenario attempts so callers need not run them twice', async () => {
    const { baselineExtra, defendedExtra } = await compare();
    expect(baselineExtra).toHaveLength(BUILTIN_SCENARIOS.length);
    expect(defendedExtra).toHaveLength(BUILTIN_SCENARIOS.length);
    expect(baselineExtra.every((a) => a.success)).toBe(true);
    expect(defendedExtra.every((a) => !a.success)).toBe(true);
  });

  it('counts what the stack did during the scenarios, not only during the scan', async () => {
    const withScenarios = await compare();
    const withoutScenarios = await compareDefenses({
      target: createMockAgent(),
      modules: BUILTIN_ATTACKS,
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
      defenses: createDefaultDefenses({ canary: CANARY, forbiddenTools: FORBIDDEN }),
      utility: false,
    });
    expect(withScenarios.comparison.activity.totalAttempts).toBe(
      withoutScenarios.comparison.activity.totalAttempts + BUILTIN_SCENARIOS.length,
    );
    expect(withScenarios.comparison.activity.quarantinedIngests).toBeGreaterThan(
      withoutScenarios.comparison.activity.quarantinedIngests,
    );
  });
});

describe('the scenario wrapTarget seam', () => {
  it('is identity by default — undefended scenarios are unchanged', async () => {
    const plain = await scenarioAttempts({ oracles: BUILTIN_ORACLES, seed: 42, canary: CANARY });
    expect(plain.every((a) => a.blocked === 0)).toBe(true);
    expect(plain.some((a) => a.success)).toBe(true);
  });

  it('records a refused scenario turn as blocked rather than as a plain miss', async () => {
    const defended = await scenarioAttempts({
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
      wrapTarget: (t) =>
        withDefenses(t, createDefaultDefenses({ canary: CANARY, forbiddenTools: FORBIDDEN })),
    });
    expect(defended.every((a) => !a.success)).toBe(true);
    expect(defended.some((a) => a.blocked > 0)).toBe(true);
  });
});

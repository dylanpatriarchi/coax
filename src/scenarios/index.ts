/**
 * Scenario registry + a helper that runs the built-in multi-step scenarios and
 * converts them into `Attempt`s so they score and report alongside single-turn
 * attacks. Multi-agent scenarios (inter-agent, rogue-agent) get the multi-agent
 * target; the rest use the mock.
 */
import { createMockAgent } from '../adapters/mock.js';
import { createMultiAgentMock } from '../adapters/multi-agent.js';
import { makeRng } from '../core/rng.js';
import { runScenarios, scenarioToAttempt } from '../core/scenario.js';
import type { Scenario, ScenarioContext, ScenarioResult } from '../core/scenario.js';
import type { Attempt } from '../core/runner.js';
import type { Oracle } from '../core/oracle.js';
import type { ChatModel } from '../llm/model.js';
import type { TargetAdapter } from '../core/target.js';
import { crescendoScenario } from './crescendo.js';
import { memoryPoisoningScenario } from './memory-poisoning.js';
import { interAgentScenario } from './inter-agent.js';
import { rogueAgentScenario } from './rogue-agent.js';

export const BUILTIN_SCENARIOS: readonly Scenario[] = [
  crescendoScenario,
  memoryPoisoningScenario,
  interAgentScenario,
  rogueAgentScenario,
];

/** The mock family's forbidden tools — used to arm the tool-trace oracle. */
const MOCK_FORBIDDEN = ['send_email', 'delete_file', 'run_code', 'fetch_url'];

export interface RunScenariosOptions {
  oracles: readonly Oracle[];
  seed: number;
  canary?: string;
  model?: ChatModel;
  /**
   * Decorate the target each scenario runs against — the seam a defense stack
   * enters through. Scenarios build their own targets, so without this the
   * families that ONLY exist as scenarios (crescendo, memory-poisoning,
   * inter-agent, rogue-agent) would sit in the main report yet be silently
   * absent from any baseline-vs-defended comparison.
   */
  wrapTarget?: (target: TargetAdapter) => TargetAdapter;
}

/** Anything that spans more than one agent needs the multi-agent target. */
const MULTI_AGENT_FAMILIES = new Set(['inter-agent', 'rogue-agent']);

function targetFor(scenario: Scenario, opts: RunScenariosOptions): TargetAdapter {
  const base = MULTI_AGENT_FAMILIES.has(scenario.family)
    ? createMultiAgentMock()
    : createMockAgent();
  return opts.wrapTarget ? opts.wrapTarget(base) : base;
}

export async function runBuiltinScenarios(
  opts: RunScenariosOptions,
  scenarios: readonly Scenario[] = BUILTIN_SCENARIOS,
): Promise<ScenarioResult[]> {
  return runScenarios(scenarios, (scenario): ScenarioContext => ({
    target: targetFor(scenario, opts),
    oracles: opts.oracles,
    rng: makeRng(opts.seed).derive(scenario.id),
    forbiddenTools: MOCK_FORBIDDEN,
    ...(opts.canary !== undefined ? { canary: opts.canary } : {}),
    ...(opts.model !== undefined ? { model: opts.model } : {}),
  }));
}

/** Run the built-in scenarios and flatten to Attempts for the scorer. */
export async function scenarioAttempts(opts: RunScenariosOptions): Promise<Attempt[]> {
  const results = await runBuiltinScenarios(opts);
  return results.map(scenarioToAttempt);
}

/**
 * The built-in scenarios as a `compareDefenses` extra-attempt source: called
 * once with an identity wrapper for the baseline column and once with the
 * defense stack for the defended one, so multi-turn families carry a residual
 * of their own instead of being missing from the table.
 */
export function scenarioComparisonSource(
  opts: RunScenariosOptions,
): (wrap: (target: TargetAdapter) => TargetAdapter) => Promise<Attempt[]> {
  return (wrap) => scenarioAttempts({ ...opts, wrapTarget: wrap });
}

export { crescendoScenario, memoryPoisoningScenario, interAgentScenario, rogueAgentScenario };

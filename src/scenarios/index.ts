/**
 * Scenario registry + a helper that runs the built-in multi-step scenarios and
 * converts them into `Attempt`s so they score and report alongside single-turn
 * attacks. Inter-agent scenarios get a multi-agent target; the rest use the mock.
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

export const BUILTIN_SCENARIOS: readonly Scenario[] = [
  crescendoScenario,
  memoryPoisoningScenario,
  interAgentScenario,
];

/** The mock family's forbidden tools — used to arm the tool-trace oracle. */
const MOCK_FORBIDDEN = ['send_email', 'delete_file', 'run_code', 'fetch_url'];

export interface RunScenariosOptions {
  oracles: readonly Oracle[];
  seed: number;
  canary?: string;
  model?: ChatModel;
}

function targetFor(scenario: Scenario): TargetAdapter {
  return scenario.family === 'inter-agent' ? createMultiAgentMock() : createMockAgent();
}

export async function runBuiltinScenarios(
  opts: RunScenariosOptions,
  scenarios: readonly Scenario[] = BUILTIN_SCENARIOS,
): Promise<ScenarioResult[]> {
  return runScenarios(scenarios, (scenario): ScenarioContext => ({
    target: targetFor(scenario),
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

export { crescendoScenario, memoryPoisoningScenario, interAgentScenario };

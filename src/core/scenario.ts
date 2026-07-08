/**
 * Multi-step scenarios — the mechanism for agent threats that a single-shot
 * payload can't express because they span TURNS or SESSIONS that must share
 * state:
 *   - crescendo        — escalate over several turns in one session
 *   - memory poisoning — plant in session A, exploit in session B (post-reset)
 *   - inter-agent      — drive a multi-agent target and tamper the bus
 *
 * The scan `runner` resets the target before every payload (independence); a
 * scenario instead controls resets itself via `driveTurn({ newSession })`, so
 * within-scenario turns can accumulate state while each scenario still starts
 * clean. Results convert to the same `Attempt` shape the scorer/report consume,
 * so scenario findings appear alongside single-turn ones.
 */
import { supportsInjection } from './target.js';
import type { AgentResponse, InjectedContent, TargetAdapter } from './target.js';
import type { Oracle, OracleVerdict } from './oracle.js';
import type { AttackFamily, AttackPayload, AttackSurface, Severity } from './attack.js';
import type { Rng } from './rng.js';
import type { ChatModel } from '../llm/model.js';
import type { Attempt } from './runner.js';

export interface ScenarioContext {
  target: TargetAdapter;
  oracles: readonly Oracle[];
  rng: Rng;
  canary?: string;
  forbiddenTools?: string[];
  /** Optional attacker model, for scenarios that adapt (e.g. model-driven crescendo). */
  model?: ChatModel;
}

export interface ScenarioTurn {
  index: number;
  /** True if the target was reset just before this turn (a fresh session). */
  newSession: boolean;
  message: string;
  inject?: InjectedContent;
  response: AgentResponse;
  verdicts: OracleVerdict[];
  success: boolean;
}

export interface ScenarioResult {
  id: string;
  family: AttackFamily;
  surface: AttackSurface;
  severity: Severity;
  taxonomy: string[];
  technique: string;
  turns: ScenarioTurn[];
  success: boolean;
}

export interface Scenario {
  readonly id: string;
  readonly family: AttackFamily;
  readonly surface: AttackSurface;
  readonly severity: Severity;
  readonly taxonomy: string[];
  readonly description: string;
  run(ctx: ScenarioContext): Promise<ScenarioResult>;
}

export interface DriveTurnInput {
  message: string;
  inject?: InjectedContent;
  /** Reset the target before this turn to simulate a new session. */
  newSession?: boolean;
}

/**
 * Drive one turn: optionally start a new session (reset), stage any indirect
 * content, send the message, and score the response with every oracle.
 */
export async function driveTurn(
  ctx: ScenarioContext,
  index: number,
  turn: DriveTurnInput,
): Promise<ScenarioTurn> {
  const newSession = turn.newSession ?? false;
  if (newSession && ctx.target.reset) await ctx.target.reset();

  if (turn.inject && supportsInjection(ctx.target)) {
    await ctx.target.injectContent(turn.inject);
  }

  const response = await ctx.target.sendMessage({ message: turn.message });

  const verdicts: OracleVerdict[] = [];
  for (const oracle of ctx.oracles) {
    verdicts.push(
      await oracle.evaluate({
        payload: { id: `scenario#${index}`, family: 'adaptive', surface: 'multi-turn' },
        response,
        ...(ctx.canary !== undefined ? { canary: ctx.canary } : {}),
        ...(ctx.forbiddenTools !== undefined ? { forbiddenTools: ctx.forbiddenTools } : {}),
      }),
    );
  }

  return {
    index,
    newSession,
    message: turn.message,
    ...(turn.inject ? { inject: turn.inject } : {}),
    response,
    verdicts,
    success: verdicts.some((v) => v.success),
  };
}

/** Flatten a scenario into a single `Attempt` so the scorer/report can consume it. */
export function scenarioToAttempt(result: ScenarioResult): Attempt {
  // The decisive turn is the LAST successful turn (else the last turn). Using the
  // last — not the first — success is what makes memory-poisoning attribute to the
  // post-reset re-activation turn, not the session-A plant that also leaks.
  let lastSuccess: ScenarioTurn | undefined;
  for (const t of result.turns) if (t.success) lastSuccess = t;
  const decisive = lastSuccess ?? result.turns[result.turns.length - 1];
  const transcript = result.turns
    .map((t) => `Turn ${t.index}${t.newSession ? ' (new session)' : ''}: ${t.message}`)
    .join('\n');
  const firstInject = result.turns.find((t) => t.inject)?.inject;

  const payload: AttackPayload = {
    id: result.id,
    moduleId: result.family,
    family: result.family,
    surface: result.surface,
    severity: result.severity,
    taxonomy: result.taxonomy,
    message: transcript,
    ...(firstInject ? { inject: firstInject } : {}),
    technique: `${result.technique} (${result.turns.length} turns)`,
    metadata: { turns: result.turns.length },
  };

  return {
    payload,
    response: decisive?.response ?? { output: '', toolCalls: [] },
    verdicts: decisive?.verdicts ?? [],
    success: result.success,
  };
}

/** Run every scenario against a freshly-built target and collect results. */
export async function runScenarios(
  scenarios: readonly Scenario[],
  makeCtx: (scenario: Scenario) => ScenarioContext,
): Promise<ScenarioResult[]> {
  const results: ScenarioResult[] = [];
  for (const scenario of scenarios) {
    const ctx = makeCtx(scenario);
    if (ctx.target.reset) await ctx.target.reset();
    results.push(await scenario.run(ctx));
  }
  return results;
}

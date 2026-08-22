/**
 * Convenience wiring for the adaptive attacker: wraps an attacker `ChatModel`
 * with the cost/caching controls and runs the closed loop. Kept separate from
 * the pure loop in `core/adaptive.ts` so that stays dependency-light and
 * offline-testable.
 *
 * The model now comes from `resolveModel()` when the caller doesn't pass one —
 * a configured `.env` (Anthropic/OpenAI/self-hosted) just works, and with
 * nothing configured that still resolves to local Ollama, exactly as this file
 * hardcoded before. Under `COAX_OFFLINE` there is no model to resolve, so an
 * explicit one is required rather than a socket being opened behind the flag.
 */
import { runAdaptiveAttack } from '../core/adaptive.js';
import type { AdaptiveResult } from '../core/adaptive.js';
import type { AttackPayload } from '../core/attack.js';
import type { Attempt } from '../core/runner.js';
import type { Oracle } from '../core/oracle.js';
import type { TargetAdapter } from '../core/target.js';
import { CachingModel, CallBudget } from '../llm/model.js';
import type { ChatModel } from '../llm/model.js';
import { resolveModel } from '../llm/resolve.js';
import { makeRng } from '../core/rng.js';

export interface AdaptiveRunOptions {
  target: TargetAdapter;
  oracles: readonly Oracle[];
  goal: string;
  canary?: string;
  forbiddenTools?: string[];
  seed?: number;
  maxIterations?: number;
  /** Max attacker-model calls (cost cap). Defaults to maxIterations. */
  maxModelCalls?: number;
  /** Attacker model. Defaults to whatever the environment configures. */
  model?: ChatModel;
  /** True multi-turn crescendo: keep one session across iterations. */
  persist?: boolean;
}

export async function runAdaptive(opts: AdaptiveRunOptions): Promise<AdaptiveResult> {
  const maxIterations = opts.maxIterations ?? 6;
  const budget = new CallBudget(opts.maxModelCalls ?? maxIterations);
  const attacker = opts.model ?? resolveModel();
  if (!attacker) {
    throw new Error(
      'runAdaptive: no attacker model available — COAX_OFFLINE is set (or COAX_PROVIDER=none). ' +
        'Pass an explicit `model` (e.g. a scripted one) to run the loop offline.',
    );
  }
  // A resolved model already carries the env-wide budget; this wrapper adds the
  // tighter per-run cap (maxModelCalls, default = maxIterations) on top.
  const model = new CachingModel(attacker, budget);

  return runAdaptiveAttack({
    rng: makeRng(opts.seed ?? 42),
    target: opts.target,
    oracles: opts.oracles,
    model,
    goal: opts.goal,
    ...(opts.canary !== undefined ? { canary: opts.canary } : {}),
    ...(opts.forbiddenTools !== undefined ? { forbiddenTools: opts.forbiddenTools } : {}),
    maxIterations,
    ...(opts.persist !== undefined ? { persist: opts.persist } : {}),
  });
}

/**
 * Fold an adaptive run into the same `Attempt` stream as the static suite, so
 * one closed-loop attack scores, weights, and reports exactly like a generated
 * payload instead of living in a parallel format nobody renders. Each ROUND is
 * one attempt: that is what makes "the attacker needed 4 tries" visible in the
 * ASR rather than collapsing to a single pass/fail.
 */
export function adaptiveAttempts(result: AdaptiveResult): Attempt[] {
  return result.rounds.map((round) => {
    const payload: AttackPayload = {
      id: `adaptive/loop#${round.iteration}`,
      moduleId: 'adaptive',
      family: 'adaptive',
      surface: round.inject ? 'indirect' : 'direct',
      // An adaptive attacker escalates until an oracle fires; treat every round
      // as high-severity so a hit is weighted like the targeted attack it is.
      severity: 'high',
      taxonomy: ['LLM01', 'ASI01'],
      message: round.message,
      ...(round.inject ? { inject: round.inject } : {}),
      technique: `adaptive iteration ${round.iteration}: ${round.reasoning}`,
      metadata: {
        goal: result.goal,
        iteration: round.iteration,
        stoppedBy: result.stoppedBy,
      },
    };
    return {
      payload,
      response: round.response,
      verdicts: round.verdicts,
      success: round.success,
    };
  });
}

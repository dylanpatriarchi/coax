/**
 * Convenience wiring for the adaptive attacker: wraps an attacker `ChatModel`
 * with the cost/caching controls and runs the closed loop. Defaults the model to
 * local Ollama so real runs need no cloud key. Kept separate from the pure loop
 * in `core/adaptive.ts` so that stays dependency-light and offline-testable.
 */
import { runAdaptiveAttack } from '../core/adaptive.js';
import type { AdaptiveResult } from '../core/adaptive.js';
import type { Oracle } from '../core/oracle.js';
import type { TargetAdapter } from '../core/target.js';
import { CachingModel, CallBudget } from '../llm/model.js';
import type { ChatModel } from '../llm/model.js';
import { ollamaModel } from '../llm/ollama-model.js';
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
  /** Attacker model. Defaults to local Ollama. */
  model?: ChatModel;
}

export async function runAdaptive(opts: AdaptiveRunOptions): Promise<AdaptiveResult> {
  const maxIterations = opts.maxIterations ?? 6;
  const budget = new CallBudget(opts.maxModelCalls ?? maxIterations);
  const model = new CachingModel(opts.model ?? ollamaModel(), budget);

  return runAdaptiveAttack({
    rng: makeRng(opts.seed ?? 42),
    target: opts.target,
    oracles: opts.oracles,
    model,
    goal: opts.goal,
    ...(opts.canary !== undefined ? { canary: opts.canary } : {}),
    ...(opts.forbiddenTools !== undefined ? { forbiddenTools: opts.forbiddenTools } : {}),
    maxIterations,
  });
}

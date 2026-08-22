/**
 * Minimal LLM client layer for the policy (LLM-judge) oracle and the adaptive
 * attacker (milestone 6).
 *
 * Everything a judge/attacker needs is a `ChatModel.complete(prompt)`. On top of
 * that this file provides the controls the spec requires for ANY live model use:
 *   - `CallBudget`   — hard cap on call count and estimated USD (cost control).
 *                      Real spend is charged via the model's optional
 *                      `estimateUsd` hook (see `pricing.ts`), so the money
 *                      ceiling reflects what a scan actually costs.
 *   - `CachingModel` — deterministic in-memory cache so identical prompts cost
 *                      nothing on repeat and scans stay reproducible.
 *   - `scriptedModel`— a fully-offline fake used by tests and CI.
 */

export interface ChatModel {
  readonly id: string;
  complete(prompt: string): Promise<string>;
  /**
   * Estimated USD for one completion, so `CallBudget`'s money ceiling is charged
   * with real spend rather than call count alone. Optional: a model that omits
   * it (a local one, a scripted fake) simply costs nothing.
   */
  estimateUsd?(prompt: string, completion: string): number;
}

export class BudgetExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BudgetExceededError';
  }
}

/** Hard ceiling on model usage. `consume()` throws once a limit is hit. */
export class CallBudget {
  private calls = 0;
  private usd = 0;

  constructor(
    private readonly maxCalls: number,
    private readonly maxUsd: number = Number.POSITIVE_INFINITY,
  ) {}

  get spentCalls(): number {
    return this.calls;
  }

  get spentUsd(): number {
    return this.usd;
  }

  remainingCalls(): number {
    return Math.max(0, this.maxCalls - this.calls);
  }

  remainingUsd(): number {
    return Math.max(0, this.maxUsd - this.usd);
  }

  /** Charge one call (+ optional cost). Throws BEFORE overspending. */
  consume(usd = 0): void {
    if (this.calls + 1 > this.maxCalls) {
      throw new BudgetExceededError(`call budget exhausted (max ${this.maxCalls} calls)`);
    }
    if (this.usd + usd > this.maxUsd) {
      throw new BudgetExceededError(`USD budget exhausted (max $${this.maxUsd})`);
    }
    this.calls += 1;
    this.usd += usd;
  }

  /**
   * Record spend that already happened (a call's real cost is only known once
   * the response is back). Deliberately does NOT throw: the money is gone and
   * throwing would only discard a response we already paid for. The ceiling
   * bites on the NEXT `consume()`, which sees the accumulated total.
   */
  charge(usd: number): void {
    if (!Number.isFinite(usd) || usd <= 0) return;
    this.usd += usd;
  }
}

/** FNV-1a hash of a string — stable cache key, no crypto needed. */
function hash(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

/** Wraps a model with an in-memory cache and an optional call budget. */
export class CachingModel implements ChatModel {
  readonly id: string;
  private readonly cache = new Map<string, string>();

  constructor(
    private readonly inner: ChatModel,
    private readonly budget?: CallBudget,
  ) {
    this.id = `cached:${inner.id}`;
  }

  async complete(prompt: string): Promise<string> {
    const key = hash(prompt);
    const hit = this.cache.get(key);
    // A cache hit costs nothing, so it neither consumes a call nor spends money.
    if (hit !== undefined) return hit;
    this.budget?.consume();
    const out = await this.inner.complete(prompt);
    // Charge the real (estimated) spend now that the completion length is known.
    this.budget?.charge(this.estimateUsd(prompt, out));
    this.cache.set(key, out);
    return out;
  }

  estimateUsd(prompt: string, completion: string): number {
    return this.inner.estimateUsd?.(prompt, completion) ?? 0;
  }

  get cacheSize(): number {
    return this.cache.size;
  }
}

/**
 * A deterministic offline model: `respond(prompt) => text`. Used by tests and by
 * CI so the judge path is exercised without any network or real model.
 */
export function scriptedModel(respond: (prompt: string) => string, id = 'scripted'): ChatModel {
  return {
    id,
    complete: async (prompt: string) => respond(prompt),
  };
}

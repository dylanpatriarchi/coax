/**
 * Per-model price table + a cheap token estimator.
 *
 * `CallBudget` has always supported a USD ceiling, but nothing ever charged it —
 * so `COAX_MAX_USD` was decoration. A scan can fan out to hundreds of judge
 * calls, and "200 calls" means a very different bill on a local model than on a
 * frontier one, so the cost cap has to be denominated in money, not calls.
 *
 * We deliberately do NOT pull a token counter dependency in: COAX only needs to
 * know when to STOP, not to invoice. A chars/4 approximation is within a factor
 * of ~1.3 for English prompts, and unknown models are priced at the most
 * expensive tier we know about — both biases make the budget stop EARLY rather
 * than overspend, which is the safe direction for a cost guard.
 */

export interface ModelPrice {
  /** USD per 1M input (prompt) tokens. */
  inputPerMTok: number;
  /** USD per 1M output (completion) tokens. */
  outputPerMTok: number;
}

/**
 * Published list prices, keyed by model-id prefix (longest match wins). Rates
 * change; this is a guard rail, not a billing system — override with
 * `estimateUsd`'s `price` argument if you need exact numbers.
 */
export const MODEL_PRICES: Readonly<Record<string, ModelPrice>> = {
  // Anthropic
  'claude-fable-5': { inputPerMTok: 10, outputPerMTok: 50 },
  'claude-opus-5': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-opus-4': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-sonnet-5': { inputPerMTok: 3, outputPerMTok: 15 },
  'claude-sonnet-4': { inputPerMTok: 3, outputPerMTok: 15 },
  'claude-haiku-4': { inputPerMTok: 1, outputPerMTok: 5 },
  // OpenAI
  'gpt-4o-mini': { inputPerMTok: 0.15, outputPerMTok: 0.6 },
  'gpt-4o': { inputPerMTok: 2.5, outputPerMTok: 10 },
  'gpt-4.1-mini': { inputPerMTok: 0.4, outputPerMTok: 1.6 },
  'gpt-4.1': { inputPerMTok: 2, outputPerMTok: 8 },
  // Self-hosted / local: metered in electricity, not dollars.
  ollama: { inputPerMTok: 0, outputPerMTok: 0 },
  local: { inputPerMTok: 0, outputPerMTok: 0 },
};

/** Charged when the model id matches nothing — the priciest tier we know. */
export const FALLBACK_PRICE: ModelPrice = { inputPerMTok: 10, outputPerMTok: 50 };

/** Strip a `provider:` / `cached:` wrapper so wrapped ids still price correctly. */
function bareId(modelId: string): string {
  const last = modelId.split(':').pop() ?? modelId;
  return last.toLowerCase();
}

/** Longest-prefix lookup. Never throws — unknown ids get `FALLBACK_PRICE`. */
export function priceFor(modelId: string): ModelPrice {
  const id = bareId(modelId);
  // A local endpoint is free regardless of which model it serves.
  if (/^(ollama|local):/i.test(modelId)) return MODEL_PRICES.ollama!;
  let best: { key: string; price: ModelPrice } | undefined;
  for (const [key, price] of Object.entries(MODEL_PRICES)) {
    if (id.startsWith(key) && (!best || key.length > best.key.length)) best = { key, price };
  }
  return best?.price ?? FALLBACK_PRICE;
}

/** Rough token count: ~4 characters per token, floored at 1 for non-empty text. */
export function approxTokens(text: string): number {
  if (text.length === 0) return 0;
  return Math.max(1, Math.ceil(text.length / 4));
}

/** Estimated USD for one completion. Pass `price` to override the table. */
export function estimateUsd(
  modelId: string,
  prompt: string,
  completion: string,
  price: ModelPrice = priceFor(modelId),
): number {
  return (
    (approxTokens(prompt) * price.inputPerMTok + approxTokens(completion) * price.outputPerMTok) /
    1_000_000
  );
}

import { describe, expect, it } from 'vitest';
import { approxTokens, estimateUsd, FALLBACK_PRICE, priceFor } from './pricing.js';
import { BudgetExceededError, CachingModel, CallBudget, scriptedModel } from './model.js';
import type { ChatModel } from './model.js';

describe('priceFor', () => {
  it('matches the longest known prefix', () => {
    expect(priceFor('claude-opus-5')).toEqual({ inputPerMTok: 5, outputPerMTok: 25 });
    expect(priceFor('gpt-4o-mini')).toEqual({ inputPerMTok: 0.15, outputPerMTok: 0.6 });
    expect(priceFor('gpt-4o')).toEqual({ inputPerMTok: 2.5, outputPerMTok: 10 });
  });

  it('sees through provider and cache prefixes', () => {
    expect(priceFor('cached:anthropic:claude-sonnet-5')).toEqual(priceFor('claude-sonnet-5'));
  });

  it('prices local models at zero', () => {
    expect(priceFor('ollama:qwen3.5:0.8b').inputPerMTok).toBe(0);
  });

  it('falls back to the priciest known tier for unknown ids', () => {
    expect(priceFor('some-new-frontier-model')).toEqual(FALLBACK_PRICE);
  });
});

describe('estimateUsd', () => {
  it('is zero for empty text and grows with length', () => {
    expect(approxTokens('')).toBe(0);
    expect(estimateUsd('claude-opus-5', '', '')).toBe(0);
    const small = estimateUsd('claude-opus-5', 'a'.repeat(400), 'b'.repeat(40));
    const large = estimateUsd('claude-opus-5', 'a'.repeat(4000), 'b'.repeat(400));
    expect(large).toBeGreaterThan(small);
  });

  it('charges output tokens more than input tokens', () => {
    const text = 'a'.repeat(4000);
    expect(estimateUsd('claude-opus-5', '', text)).toBeGreaterThan(
      estimateUsd('claude-opus-5', text, ''),
    );
  });
});

/** A scripted model that also declares a price, like the real clients do. */
function pricedModel(usdPerCall: number): ChatModel {
  return { ...scriptedModel((p) => `echo:${p}`, 'priced'), estimateUsd: () => usdPerCall };
}

describe('CallBudget cost accounting', () => {
  it('records spend without throwing, then refuses the next call', () => {
    const budget = new CallBudget(10, 0.05);
    budget.charge(0.06); // the money is already gone — do not discard the response
    expect(budget.spentUsd).toBeCloseTo(0.06);
    expect(budget.remainingUsd()).toBe(0);
    expect(() => budget.consume()).toThrow(BudgetExceededError);
  });

  it('ignores nonsensical charges', () => {
    const budget = new CallBudget(1, 1);
    budget.charge(Number.NaN);
    budget.charge(-1);
    expect(budget.spentUsd).toBe(0);
  });
});

describe('CachingModel spend', () => {
  it('charges the model estimate to the budget on a miss and nothing on a hit', async () => {
    const budget = new CallBudget(10, 1);
    const model = new CachingModel(pricedModel(0.25), budget);
    await model.complete('a');
    expect(budget.spentUsd).toBeCloseTo(0.25);
    await model.complete('a');
    expect(budget.spentUsd).toBeCloseTo(0.25);
    expect(budget.spentCalls).toBe(1);
  });

  it('lets the USD ceiling stop a run that the call cap would not', async () => {
    const budget = new CallBudget(100, 0.5);
    const model = new CachingModel(pricedModel(0.4), budget);
    await model.complete('a');
    await model.complete('b');
    await expect(model.complete('c')).rejects.toThrow(/USD budget/);
    expect(budget.spentCalls).toBe(2);
  });

  it('costs nothing when the inner model declares no price', async () => {
    const budget = new CallBudget(5, 0.01);
    const model = new CachingModel(scriptedModel((p) => p), budget);
    await model.complete('a');
    expect(budget.spentUsd).toBe(0);
  });
});

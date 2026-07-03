import { describe, expect, it } from 'vitest';
import { BudgetExceededError, CachingModel, CallBudget, scriptedModel } from './model.js';

describe('CallBudget', () => {
  it('allows up to the cap then throws', () => {
    const b = new CallBudget(2);
    b.consume();
    b.consume();
    expect(() => b.consume()).toThrow(BudgetExceededError);
    expect(b.spentCalls).toBe(2);
    expect(b.remainingCalls()).toBe(0);
  });

  it('enforces a USD ceiling', () => {
    const b = new CallBudget(100, 0.05);
    b.consume(0.04);
    expect(() => b.consume(0.02)).toThrow(/USD budget/);
  });
});

describe('CachingModel', () => {
  it('caches identical prompts and only charges the budget once', async () => {
    let calls = 0;
    const budget = new CallBudget(10);
    const model = new CachingModel(
      scriptedModel((p) => {
        calls++;
        return `echo:${p}`;
      }),
      budget,
    );
    expect(await model.complete('hi')).toBe('echo:hi');
    expect(await model.complete('hi')).toBe('echo:hi');
    expect(calls).toBe(1);
    expect(budget.spentCalls).toBe(1);
    expect(model.cacheSize).toBe(1);
  });

  it('propagates budget exhaustion for new prompts', async () => {
    const model = new CachingModel(scriptedModel((p) => p), new CallBudget(1));
    await model.complete('a');
    await expect(model.complete('b')).rejects.toThrow(BudgetExceededError);
  });
});

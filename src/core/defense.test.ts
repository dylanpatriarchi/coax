import { describe, expect, it } from 'vitest';
import { allow, block, isDefendedTarget, withDefenses } from './defense.js';
import type { Defense } from './defense.js';
import type { AgentInput, AgentResponse, InjectedContent, TargetAdapter, ToolSpec } from './target.js';
import { supportsInjection, supportsTools } from './target.js';

/** A target with EVERY optional capability. */
function fullTarget(): TargetAdapter & { staged: InjectedContent[]; resets: number; seen: string[] } {
  const staged: InjectedContent[] = [];
  const seen: string[] = [];
  const t = {
    name: 'full',
    staged,
    resets: 0,
    seen,
    async sendMessage(input: AgentInput): Promise<AgentResponse> {
      seen.push(input.message);
      return {
        output: `echo: ${input.message}`,
        toolCalls: [{ id: 'c1', name: 'send_email', arguments: { to: 'a@b.example' } }],
      };
    },
    async injectContent(content: InjectedContent): Promise<void> {
      staged.push(content);
    },
    async describeTools(): Promise<ToolSpec[]> {
      return [{ name: 'send_email', description: '', parameters: {}, forbidden: true }];
    },
    async reset(): Promise<void> {
      t.resets += 1;
    },
  };
  return t;
}

/** A target with NO optional capability — chat only. */
const bareTarget: TargetAdapter = {
  name: 'bare',
  async sendMessage(): Promise<AgentResponse> {
    return { output: 'hi', toolCalls: [] };
  },
};

const noopDefense: Defense = {
  id: 'noop',
  description: 'does nothing',
  limitations: 'everything',
};

describe('withDefenses capability preservation', () => {
  it('keeps every optional capability the inner target has', () => {
    const inner = fullTarget();
    const d = withDefenses(inner, [noopDefense]);
    expect(supportsInjection(d)).toBe(true);
    expect(supportsTools(d)).toBe(true);
    expect(typeof d.reset).toBe('function');
  });

  it('does NOT invent capabilities the inner target lacks', () => {
    const d = withDefenses(bareTarget, [noopDefense]);
    expect(supportsInjection(d)).toBe(false);
    expect(supportsTools(d)).toBe(false);
    expect(d.reset).toBeUndefined();
  });

  it('forwards the capabilities it exposes to the inner target', async () => {
    const inner = fullTarget();
    const d = withDefenses(inner, [noopDefense]);
    await d.reset?.();
    await d.injectContent?.({ channel: 'web', source: 's', content: 'plain text' });
    expect(inner.resets).toBe(1);
    expect(inner.staged).toHaveLength(1);
    expect(await d.describeTools?.()).toEqual([
      { name: 'send_email', description: '', parameters: {}, forbidden: true },
    ]);
  });

  it('is recognisable as a defended target', () => {
    expect(isDefendedTarget(withDefenses(bareTarget, []))).toBe(true);
    expect(isDefendedTarget(bareTarget)).toBe(false);
  });
});

describe('withDefenses hooks', () => {
  const rewriter: Defense = {
    id: 'rewriter',
    description: 'uppercases the turn',
    limitations: 'nothing real',
    screenInput: (input) => allow({ ...input, message: input.message.toUpperCase() }, 'uppercased'),
  };

  it('passes the rewritten input to the inner target and records the rewrite', async () => {
    const inner = fullTarget();
    const d = withDefenses(inner, [rewriter]);
    await d.sendMessage({ message: 'hello' });
    expect(inner.seen).toEqual(['HELLO']);
    expect(d.consumeEvents()).toEqual([
      { defenseId: 'rewriter', stage: 'input', action: 'rewrote', detail: 'uppercased' },
    ]);
  });

  it('applies defenses in order, each seeing the previous one output', async () => {
    const inner = fullTarget();
    const suffix: Defense = {
      id: 'suffix',
      description: 'appends',
      limitations: 'nothing real',
      screenInput: (input) => allow({ ...input, message: `${input.message}!` }),
    };
    const d = withDefenses(inner, [rewriter, suffix]);
    await d.sendMessage({ message: 'hey' });
    expect(inner.seen).toEqual(['HEY!']);
  });

  it('drains the event log so each caller sees only its own events', async () => {
    const d = withDefenses(fullTarget(), [rewriter]);
    await d.sendMessage({ message: 'a' });
    expect(d.consumeEvents()).toHaveLength(1);
    expect(d.consumeEvents()).toHaveLength(0);
  });
});

describe('blocked-request accounting', () => {
  const refuser: Defense = {
    id: 'refuser',
    description: 'refuses everything',
    limitations: 'usefulness',
    screenInput: (input) => block(input, 'this control refuses every turn'),
  };

  it('records a block instead of silently swallowing it', async () => {
    const inner = fullTarget();
    const d = withDefenses(inner, [refuser]);
    const res = await d.sendMessage({ message: 'anything' });

    // The inner agent was never asked.
    expect(inner.seen).toEqual([]);
    // Empty output: no oracle can fire, and a blocked benign task fails utility.
    expect(res.output).toBe('');
    expect(res.toolCalls).toEqual([]);
    expect(res.trace?.[0]?.data).toMatchObject({ defense: 'refuser', blocked: true });

    const events = d.consumeEvents();
    expect(events).toEqual([
      {
        defenseId: 'refuser',
        stage: 'input',
        action: 'blocked',
        detail: 'this control refuses every turn',
      },
    ]);
  });

  it('quarantines ingested content without failing the whole turn', async () => {
    const inner = fullTarget();
    const quarantine: Defense = {
      id: 'quarantine',
      description: 'drops all ingested content',
      limitations: 'retrieval',
      screenIngest: (content) => block(content, 'ingested span refused'),
    };
    const d = withDefenses(inner, [quarantine]);
    await d.injectContent?.({ channel: 'web', source: 'x', content: 'poison' });
    const res = await d.sendMessage({ message: 'summarize' });

    expect(inner.staged).toEqual([]); // never reached the agent
    expect(res.output).toBe('echo: summarize'); // the user still got an answer
    expect(d.consumeEvents()).toEqual([
      {
        defenseId: 'quarantine',
        stage: 'ingest',
        action: 'blocked',
        detail: 'ingested span refused',
      },
    ]);
  });

  it('blocks on the way out too, and stops later defenses from seeing the response', async () => {
    const blocker: Defense = {
      id: 'egress-blocker',
      description: 'refuses responses with tool calls',
      limitations: 'text-only harms',
      screenOutput: (r) =>
        r.toolCalls.length > 0 ? block(r, 'response carried a tool call') : allow(r),
    };
    let laterSaw = 0;
    const later: Defense = {
      id: 'later',
      description: 'counts what it sees',
      limitations: 'everything',
      screenOutput: (r) => {
        laterSaw += 1;
        return allow(r);
      },
    };
    const d = withDefenses(fullTarget(), [blocker, later]);
    const res = await d.sendMessage({ message: 'go' });
    expect(res.output).toBe('');
    expect(laterSaw).toBe(0);
    expect(d.consumeEvents()[0]?.stage).toBe('output');
  });
});

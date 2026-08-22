/**
 * The defense seam — how COAX answers "did the mitigation actually help?".
 *
 * Until now COAX could only measure an undefended target: it produced an ASR and
 * stopped. That is useless to a blue team, which needs a before/after number to
 * justify a control. A `Defense` is therefore modelled exactly the way a real
 * mitigation sits in an agent stack: as a wrapper around the target that can
 * rewrite or refuse what goes IN (the user turn, and any attacker-controlled
 * content staged for ingestion) and redact or refuse what comes OUT (the text
 * and the tool calls) before the oracles ever see it.
 *
 * Two design decisions worth stating:
 *
 *  - Defenses wrap the TARGET, not the runner. A control that only existed
 *    inside COAX's harness would measure nothing about the system under test;
 *    wrapping the adapter means the same defended object can be handed to the
 *    scan, the utility suite, or a scenario, and every one of them sees the
 *    identical control.
 *
 *  - A block is EVIDENCE, not silence. When a defense refuses a request the
 *    wrapper returns an empty response and records a `DefenseEvent`, so the
 *    attempt is scored as "defended" rather than quietly vanishing. An empty
 *    response is also what makes an over-blocking defense fail the utility
 *    suite: a control that refuses everything scores 0% ASR and 0% utility, and
 *    the report shows both.
 *
 * Defenses are pure functions of their input plus their own construction-time
 * config — no clocks, no randomness — so a defended scan is as reproducible as
 * an undefended one.
 */
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
  ToolSpec,
} from './target.js';
import { supportsInjection, supportsTools } from './target.js';

/**
 * The result of one defense hook: the value to pass on, or a refusal.
 *
 * `blockedReason` is required to be a real sentence — a control that cannot say
 * why it refused is not auditable, and the reason lands verbatim in the report.
 */
export interface DefenseOutcome<T> {
  /** The (possibly rewritten) value. Ignored when `blockedReason` is set. */
  value: T;
  /** Set to refuse the request outright. */
  blockedReason?: string;
  /** Why the value was rewritten — recorded even when nothing is blocked. */
  note?: string;
}

/** Convenience constructors so the built-ins read declaratively. */
export const allow = <T>(value: T, note?: string): DefenseOutcome<T> => ({
  value,
  ...(note !== undefined ? { note } : {}),
});

export const block = <T>(value: T, blockedReason: string): DefenseOutcome<T> => ({
  value,
  blockedReason,
});

export type MaybeAsync<T> = T | Promise<T>;

/**
 * A single, composable control. Every hook is optional: a defense that only
 * screens ingested content implements only `screenIngest`.
 */
export interface Defense {
  readonly id: string;
  readonly description: string;
  /**
   * What this defense does NOT stop. Mandatory, and rendered in the report —
   * COAX measures controls, it does not market them.
   */
  readonly limitations: string;

  /** Screen or rewrite the inbound user turn. */
  screenInput?(input: AgentInput): MaybeAsync<DefenseOutcome<AgentInput>>;
  /** Screen or rewrite attacker-controlled content before the agent ingests it. */
  screenIngest?(content: InjectedContent): MaybeAsync<DefenseOutcome<InjectedContent>>;
  /** Screen, redact, or refuse the agent's response and tool calls. */
  screenOutput?(response: AgentResponse): MaybeAsync<DefenseOutcome<AgentResponse>>;
}

/** One thing a defense did during an attempt. */
export interface DefenseEvent {
  defenseId: string;
  stage: 'input' | 'ingest' | 'output';
  action: 'blocked' | 'rewrote';
  detail: string;
}

/** What the runner records per attempt when the target is defended. */
export interface DefenseTrace {
  /** True when a defense refused the turn outright (no agent response at all). */
  blocked: boolean;
  events: DefenseEvent[];
}

/** A target with a defense stack in front of it. */
export interface DefendedTarget extends TargetAdapter {
  readonly defenses: readonly Defense[];
  /** Drain the events recorded since the last call. */
  consumeEvents(): DefenseEvent[];
}

export const isDefendedTarget = (t: TargetAdapter): t is DefendedTarget =>
  Array.isArray((t as Partial<DefendedTarget>).defenses) &&
  typeof (t as Partial<DefendedTarget>).consumeEvents === 'function';

/**
 * The response a blocked turn produces: no text, no tool calls, and a trace note
 * naming the control. Empty output is deliberate — it means no oracle can fire
 * on a blocked turn, AND that a blocked benign task counts as a utility failure.
 */
function blockedResponse(defenseId: string, reason: string): AgentResponse {
  return {
    output: '',
    toolCalls: [],
    trace: [{ type: 'note', at: 0, data: { defense: defenseId, blocked: true, reason } }],
  };
}

/**
 * Wrap a target in a defense stack, preserving its capabilities.
 *
 * Capability detection is load-bearing: the runner decides whether indirect
 * injection applies by checking `injectContent`, and the scan reads
 * `describeTools` for forbidden tools. A wrapper that unconditionally declared
 * those methods would make every target look injectable; one that dropped them
 * would silently disable whole attack families. So each optional method is
 * forwarded only when the inner target actually has it.
 */
export function withDefenses(target: TargetAdapter, defenses: readonly Defense[]): DefendedTarget {
  const stack = [...defenses];
  let events: DefenseEvent[] = [];

  const record = (
    defenseId: string,
    stage: DefenseEvent['stage'],
    action: DefenseEvent['action'],
    detail: string,
  ): void => {
    events.push({ defenseId, stage, action, detail });
  };

  async function sendMessage(input: AgentInput): Promise<AgentResponse> {
    let current = input;
    for (const d of stack) {
      if (!d.screenInput) continue;
      const outcome = await d.screenInput(current);
      if (outcome.blockedReason !== undefined) {
        record(d.id, 'input', 'blocked', outcome.blockedReason);
        return blockedResponse(d.id, outcome.blockedReason);
      }
      if (outcome.note !== undefined) record(d.id, 'input', 'rewrote', outcome.note);
      current = outcome.value;
    }

    let response = await target.sendMessage(current);

    for (const d of stack) {
      if (!d.screenOutput) continue;
      const outcome = await d.screenOutput(response);
      if (outcome.blockedReason !== undefined) {
        record(d.id, 'output', 'blocked', outcome.blockedReason);
        return blockedResponse(d.id, outcome.blockedReason);
      }
      if (outcome.note !== undefined) record(d.id, 'output', 'rewrote', outcome.note);
      response = outcome.value;
    }

    return response;
  }

  /**
   * Screening ingested content QUARANTINES it rather than failing the turn: a
   * real content filter drops the poisoned document and the agent still answers
   * the user. The drop is recorded, so it stays visible as a defended attempt.
   */
  async function injectContent(content: InjectedContent): Promise<void> {
    let current = content;
    for (const d of stack) {
      if (!d.screenIngest) continue;
      const outcome = await d.screenIngest(current);
      if (outcome.blockedReason !== undefined) {
        record(d.id, 'ingest', 'blocked', outcome.blockedReason);
        return;
      }
      if (outcome.note !== undefined) record(d.id, 'ingest', 'rewrote', outcome.note);
      current = outcome.value;
    }
    if (supportsInjection(target)) await target.injectContent(current);
  }

  return {
    name: `${target.name}+defended`,
    sendMessage,
    // Capability preservation: forward ONLY what the inner target really has.
    ...(supportsInjection(target) ? { injectContent } : {}),
    ...(supportsTools(target)
      ? { describeTools: (): Promise<ToolSpec[]> => (target.describeTools as () => Promise<ToolSpec[]>)() }
      : {}),
    ...(target.reset ? { reset: (): Promise<void> => (target.reset as () => Promise<void>)() } : {}),
    defenses: stack,
    consumeEvents(): DefenseEvent[] {
      const drained = events;
      events = [];
      return drained;
    },
  };
}

/**
 * The Target adapter seam.
 *
 * Everything COAX does flows through this interface, so it can red-team ANY
 * agent — a mock, an HTTP endpoint, an OpenAI-compatible chat+tools API, or a
 * headless browser agent — without the attack/oracle code knowing which.
 *
 * The two capabilities that make this agent-aware (not just chat-aware) are:
 *   - `injectContent`: stage attacker-controlled content the agent will INGEST
 *     (a poisoned web page, document, tool result, or email). This is the
 *     channel for INDIRECT prompt injection, the core agent threat.
 *   - `describeTools` + `toolCalls` in the response: so tool-abuse attacks can
 *     target real tools/arguments and oracles can inspect the call trace.
 */
import { z } from 'zod';

/** A single tool invocation observed in the agent's trace. */
export const ToolCallSchema = z.object({
  id: z.string(),
  name: z.string(),
  arguments: z.record(z.string(), z.unknown()),
});
export type ToolCall = z.infer<typeof ToolCallSchema>;

/** A declared tool the target agent can call — used to target tool-abuse attacks. */
export const ToolSpecSchema = z.object({
  name: z.string(),
  description: z.string().default(''),
  /** JSON-schema-ish parameter description; opaque to COAX. */
  parameters: z.record(z.string(), z.unknown()).default({}),
  /** Marks a tool the agent should NOT invoke during a scan (oracle hook). */
  forbidden: z.boolean().default(false),
});
export type ToolSpec = z.infer<typeof ToolSpecSchema>;

/** An event in the agent's execution trace (best-effort; adapters may omit). */
export const TraceEventSchema = z.object({
  type: z.enum(['message', 'tool_call', 'tool_result', 'ingest', 'note']),
  at: z.number().int().nonnegative().describe('monotonic step index, not wall-clock'),
  data: z.record(z.string(), z.unknown()).default({}),
});
export type TraceEvent = z.infer<typeof TraceEventSchema>;

/** The channel through which indirect (ingested) content reaches the agent. */
export const IngestChannelSchema = z.enum(['web', 'document', 'tool_result', 'email']);
export type IngestChannel = z.infer<typeof IngestChannelSchema>;

/** Attacker-controlled content the agent will read — the indirect-injection payload carrier. */
export const InjectedContentSchema = z.object({
  channel: IngestChannelSchema,
  source: z.string().describe('url / filename / sender the agent believes this came from'),
  content: z.string(),
});
export type InjectedContent = z.infer<typeof InjectedContentSchema>;

/** One turn of input sent to the target agent. */
export const AgentInputSchema = z.object({
  message: z.string(),
  /** Optional conversation id so multi-turn / crescendo attacks share state. */
  conversationId: z.string().optional(),
});
export type AgentInput = z.infer<typeof AgentInputSchema>;

/** What the target returns for one turn. */
export const AgentResponseSchema = z.object({
  output: z.string(),
  toolCalls: z.array(ToolCallSchema).default([]),
  trace: z.array(TraceEventSchema).optional(),
});
export type AgentResponse = z.infer<typeof AgentResponseSchema>;

/**
 * The adapter every target implements. Only `name` and `sendMessage` are
 * required; the optional methods unlock indirect-injection, tool-abuse, and
 * multi-turn attack families when the target supports them.
 */
export interface TargetAdapter {
  readonly name: string;

  /** Drive one turn of the agent. */
  sendMessage(input: AgentInput): Promise<AgentResponse>;

  /**
   * Stage indirect content the agent will ingest on a subsequent `sendMessage`.
   * Presence of this method is how the runner decides indirect-injection
   * attacks apply to a target.
   */
  injectContent?(content: InjectedContent): Promise<void>;

  /** Declare the agent's tools so tool-abuse attacks can target real arguments. */
  describeTools?(): Promise<ToolSpec[]>;

  /** Clear conversation / injected / memory state between independent attempts. */
  reset?(): Promise<void>;
}

/** Narrowing helpers so callers can feature-detect optional capabilities. */
export const supportsInjection = (
  t: TargetAdapter,
): t is TargetAdapter & Required<Pick<TargetAdapter, 'injectContent'>> =>
  typeof t.injectContent === 'function';

export const supportsTools = (
  t: TargetAdapter,
): t is TargetAdapter & Required<Pick<TargetAdapter, 'describeTools'>> =>
  typeof t.describeTools === 'function';

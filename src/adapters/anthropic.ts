/**
 * Anthropic Messages API target adapter.
 *
 * COAX could already red-team an OpenAI-compatible agent but not a Claude one,
 * and the two wire formats differ in exactly the places the attack surface lives:
 * the system prompt is a top-level field (not a message), tools use
 * `input_schema` with already-parsed `input` objects, and the reply is a list of
 * content blocks where `tool_use` sits beside `text`. Those blocks are what the
 * tool-trace oracle needs, so they are surfaced as `toolCalls` rather than
 * flattened into prose.
 *
 * Indirect content is delivered inside the USER turn as extra text blocks — the
 * Messages API has no free-standing `tool` role, and a poisoned document the
 * agent is asked to summarise arrives in exactly that position in real agents.
 *
 * Modelled on `adapters/openai.ts`, including the `fetchImpl` seam that keeps it
 * offline-testable. `temperature` is only sent when explicitly configured:
 * current Claude models reject sampling parameters.
 */
import { z } from 'zod';
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
  ToolCall,
  ToolSpec,
  TraceEvent,
} from '../core/target.js';
import { ANTHROPIC_VERSION, DEFAULT_ANTHROPIC_MODEL } from '../llm/anthropic-model.js';

export interface AnthropicAdapterConfig {
  baseUrl?: string;
  apiKey?: string;
  model?: string;
  systemPrompt?: string;
  canary?: string;
  tools?: ToolSpec[];
  /** Required by the API; leave room for thinking on current models. */
  maxTokens?: number;
  /** Only sent when set — current models 400 on sampling parameters. */
  temperature?: number;
  anthropicVersion?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const MessageResponseSchema = z.object({
  content: z.array(
    z.object({
      type: z.string(),
      text: z.string().optional(),
      id: z.string().optional(),
      name: z.string().optional(),
      input: z.record(z.string(), z.unknown()).optional(),
    }),
  ),
  stop_reason: z.string().nullable().optional(),
});

interface TextBlock {
  type: 'text';
  text: string;
}

export class AnthropicAgent implements TargetAdapter {
  readonly name: string;
  private readonly staged: InjectedContent[] = [];
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;
  private readonly model: string;

  constructor(private readonly cfg: AnthropicAdapterConfig = {}) {
    this.model = cfg.model ?? DEFAULT_ANTHROPIC_MODEL;
    this.baseUrl = (cfg.baseUrl ?? 'https://api.anthropic.com').replace(/\/+$/, '');
    this.name = `anthropic:${this.model}`;
    this.fetchImpl = cfg.fetchImpl ?? fetch;
  }

  async describeTools(): Promise<ToolSpec[]> {
    return (this.cfg.tools ?? []).map((t) => ({ ...t }));
  }

  async injectContent(content: InjectedContent): Promise<void> {
    this.staged.push(content);
  }

  async reset(): Promise<void> {
    this.staged.length = 0;
  }

  private systemPrompt(): string | undefined {
    if (!this.cfg.systemPrompt) return undefined;
    return this.cfg.canary
      ? this.cfg.systemPrompt.replace('{{CANARY}}', this.cfg.canary)
      : this.cfg.systemPrompt;
  }

  /** Staged (attacker-controlled) content first, then the user's real ask. */
  private userBlocks(input: AgentInput): TextBlock[] {
    const blocks: TextBlock[] = this.staged.map((c) => ({
      type: 'text',
      text: `[Ingested ${c.channel} from ${c.source}]\n${c.content}`,
    }));
    blocks.push({ type: 'text', text: input.message });
    return blocks;
  }

  private toolsPayload(): unknown[] | undefined {
    if (!this.cfg.tools || this.cfg.tools.length === 0) return undefined;
    return this.cfg.tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema:
        Object.keys(t.parameters).length > 0 ? t.parameters : { type: 'object', properties: {} },
    }));
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    const system = this.systemPrompt();
    const blocks = this.userBlocks(input);
    const tools = this.toolsPayload();
    const body = {
      model: this.model,
      max_tokens: this.cfg.maxTokens ?? 4096,
      messages: [{ role: 'user', content: blocks }],
      ...(system !== undefined ? { system } : {}),
      ...(this.cfg.temperature !== undefined ? { temperature: this.cfg.temperature } : {}),
      ...(tools ? { tools } : {}),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 60_000);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/v1/messages`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'anthropic-version': this.cfg.anthropicVersion ?? ANTHROPIC_VERSION,
          ...(this.cfg.apiKey ? { 'x-api-key': this.cfg.apiKey } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`Anthropic ${res.status}: ${await res.text()}`);
      }
      const parsed = MessageResponseSchema.parse(await res.json());

      const output = parsed.content
        .filter((b) => b.type === 'text')
        .map((b) => b.text ?? '')
        .join('');
      const toolCalls: ToolCall[] = parsed.content
        .filter((b) => b.type === 'tool_use')
        .map((b, i) => ({
          id: b.id ?? `call_${i}`,
          name: b.name ?? 'unknown',
          arguments: b.input ?? {},
        }));

      const trace: TraceEvent[] = [];
      if (system !== undefined)
        trace.push({ type: 'message', at: 0, data: { role: 'system', content: system } });
      for (const b of blocks) {
        // Everything staged before the user's own message came in via ingest.
        const isIngest = b !== blocks[blocks.length - 1];
        trace.push({
          type: isIngest ? 'ingest' : 'message',
          at: trace.length,
          data: { role: 'user', content: b.text },
        });
      }
      for (const tc of toolCalls)
        trace.push({ type: 'tool_call', at: trace.length, data: { ...tc } });

      return { output, toolCalls, trace };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function createAnthropicAgent(config: AnthropicAdapterConfig = {}): AnthropicAgent {
  return new AnthropicAgent(config);
}

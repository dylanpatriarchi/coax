/**
 * OpenAI-compatible chat+tools target adapter.
 *
 * Talks to any `/chat/completions` endpoint (OpenAI, Azure, together, local
 * llama.cpp/vLLM, etc.). Maps declared tools into the `tools` function schema and
 * surfaces the model's `tool_calls` in the `AgentResponse` so tool-abuse attacks
 * and the tool-trace oracle work. Indirect content is staged as prior context
 * messages (the ingest channel). A `fetchImpl` seam keeps it offline-testable.
 */
import { z } from 'zod';
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
  ToolCall,
  ToolSpec,
} from '../core/target.js';

export interface OpenAIAdapterConfig {
  baseUrl?: string;
  apiKey?: string;
  model: string;
  systemPrompt?: string;
  canary?: string;
  tools?: ToolSpec[];
  temperature?: number;
  seed?: number;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const ChatResponseSchema = z.object({
  choices: z
    .array(
      z.object({
        message: z.object({
          content: z.string().nullable().default(''),
          tool_calls: z
            .array(
              z.object({
                id: z.string().default('call'),
                function: z.object({ name: z.string(), arguments: z.string().default('{}') }),
              }),
            )
            .optional(),
        }),
      }),
    )
    .min(1),
});

interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
}

export class OpenAIAgent implements TargetAdapter {
  readonly name: string;
  private readonly staged: InjectedContent[] = [];
  private readonly fetchImpl: typeof fetch;
  private readonly baseUrl: string;

  constructor(private readonly cfg: OpenAIAdapterConfig) {
    if (!cfg.model) throw new Error('OpenAIAgent: model is required');
    this.baseUrl = cfg.baseUrl ?? 'https://api.openai.com/v1';
    this.name = `openai:${cfg.model}`;
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

  private messages(input: AgentInput): ChatMessage[] {
    const msgs: ChatMessage[] = [];
    if (this.cfg.systemPrompt) {
      const sys = this.cfg.canary
        ? this.cfg.systemPrompt.replace('{{CANARY}}', this.cfg.canary)
        : this.cfg.systemPrompt;
      msgs.push({ role: 'system', content: sys });
    }
    for (const c of this.staged) {
      msgs.push({ role: 'tool', content: `[Ingested ${c.channel} from ${c.source}]\n${c.content}` });
    }
    msgs.push({ role: 'user', content: input.message });
    return msgs;
  }

  private toolsPayload(): unknown[] | undefined {
    if (!this.cfg.tools || this.cfg.tools.length === 0) return undefined;
    return this.cfg.tools.map((t) => ({
      type: 'function',
      function: { name: t.name, description: t.description, parameters: t.parameters },
    }));
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    const tools = this.toolsPayload();
    const body = {
      model: this.cfg.model,
      messages: this.messages(input),
      temperature: this.cfg.temperature ?? 0,
      ...(this.cfg.seed !== undefined ? { seed: this.cfg.seed } : {}),
      ...(tools ? { tools } : {}),
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 60_000);
    try {
      const res = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.cfg.apiKey ? { authorization: `Bearer ${this.cfg.apiKey}` } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`OpenAI ${res.status}: ${await res.text()}`);
      }
      const parsed = ChatResponseSchema.parse(await res.json());
      const message = parsed.choices[0]!.message;
      const toolCalls: ToolCall[] = (message.tool_calls ?? []).map((tc) => {
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(tc.function.arguments) as Record<string, unknown>;
        } catch {
          args = { _raw: tc.function.arguments };
        }
        return { id: tc.id, name: tc.function.name, arguments: args };
      });
      return { output: message.content ?? '', toolCalls };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function createOpenAIAgent(config: OpenAIAdapterConfig): OpenAIAgent {
  return new OpenAIAgent(config);
}

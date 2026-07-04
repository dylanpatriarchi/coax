/**
 * Generic HTTP target adapter.
 *
 * Drives any agent exposed over an HTTP endpoint. The request/response shapes are
 * configurable so it fits arbitrary APIs: `buildBody` maps the message + staged
 * indirect content into the request, `parseResponse` maps the reply into an
 * `AgentResponse`. A `fetchImpl` seam makes it fully offline-testable.
 *
 * Indirect injection is supported by staging content that `buildBody` includes
 * in the request (default: an `ingested` array the endpoint is expected to feed
 * to its agent as context).
 */
import { z } from 'zod';
import {
  AgentResponseSchema,
  type AgentInput,
  type AgentResponse,
  type InjectedContent,
  type TargetAdapter,
  type ToolSpec,
} from '../core/target.js';

export interface HttpAdapterConfig {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  tools?: ToolSpec[];
  /** Build the request body. Default: `{ message, ingested }`. */
  buildBody?: (input: AgentInput, ingested: InjectedContent[]) => unknown;
  /** Map the parsed JSON response into an AgentResponse. Default: identity-ish. */
  parseResponse?: (json: unknown) => AgentResponse;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

const DefaultResponseSchema = z.object({
  output: z.string(),
  toolCalls: z
    .array(z.object({ id: z.string(), name: z.string(), arguments: z.record(z.string(), z.unknown()) }))
    .default([]),
});

export class HttpAgent implements TargetAdapter {
  readonly name: string;
  private readonly staged: InjectedContent[] = [];
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly cfg: HttpAdapterConfig) {
    if (!cfg.url) throw new Error('HttpAgent: url is required');
    this.name = `http:${cfg.url}`;
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

  private buildBody(input: AgentInput): unknown {
    if (this.cfg.buildBody) return this.cfg.buildBody(input, this.staged);
    return { message: input.message, ingested: this.staged };
  }

  private parse(json: unknown): AgentResponse {
    if (this.cfg.parseResponse) return this.cfg.parseResponse(json);
    return AgentResponseSchema.parse(DefaultResponseSchema.parse(json));
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 60_000);
    try {
      const res = await this.fetchImpl(this.cfg.url, {
        method: this.cfg.method ?? 'POST',
        headers: { 'content-type': 'application/json', ...(this.cfg.headers ?? {}) },
        body: JSON.stringify(this.buildBody(input)),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      }
      return this.parse(await res.json());
    } finally {
      clearTimeout(timer);
    }
  }
}

export function createHttpAgent(config: HttpAdapterConfig): HttpAgent {
  return new HttpAgent(config);
}

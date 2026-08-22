/**
 * `ChatModel` over any OpenAI-compatible `/chat/completions` endpoint.
 *
 * Until now `src/llm/` shipped only an Ollama client, so the LLM-judge oracle
 * and the adaptive attacker could only run against a local model — even though
 * `.env.example` has always advertised `OPENAI_API_KEY`/`OPENAI_BASE_URL`. The
 * `/chat/completions` shape is the de-facto lingua franca (OpenAI, Azure, vLLM,
 * llama.cpp, together, Ollama's own `/v1`), so ONE client with a configurable
 * base URL covers every hosted and self-hosted judge a user is likely to point
 * COAX at.
 *
 * Conventions kept identical to `adapters/openai.ts`: zod-validated parsing (a
 * malformed response must fail loudly, never silently score as "no violation"),
 * an AbortController timeout, and a `fetchImpl` seam so the whole thing is
 * offline-testable. The API key lives only in the request headers.
 */
import { z } from 'zod';
import type { ChatModel } from './model.js';
import { estimateUsd } from './pricing.js';
import { httpError, isAbort, LlmTimeoutError } from './http-error.js';

export interface OpenAIModelOptions {
  /** Any OpenAI-compatible root, e.g. `http://localhost:8000/v1`. */
  baseUrl?: string;
  model?: string;
  apiKey?: string;
  /** Omitted by default: some current models reject sampling parameters. */
  temperature?: number;
  seed?: number;
  maxTokens?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

const ChatCompletionSchema = z.object({
  choices: z
    .array(z.object({ message: z.object({ content: z.string().nullable().default('') }) }))
    .min(1),
});

export function openAIModel(opts: OpenAIModelOptions = {}): ChatModel {
  const baseUrl = (opts.baseUrl ?? 'https://api.openai.com/v1').replace(/\/+$/, '');
  const model = opts.model ?? 'gpt-4o-mini';
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const doFetch = opts.fetchImpl ?? fetch;

  return {
    id: `openai:${model}`,

    estimateUsd: (prompt: string, completion: string) => estimateUsd(model, prompt, completion),

    async complete(prompt: string): Promise<string> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await doFetch(`${baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(opts.apiKey ? { authorization: `Bearer ${opts.apiKey}` } : {}),
          },
          body: JSON.stringify({
            model,
            messages: [{ role: 'user', content: prompt }],
            ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
            ...(opts.seed !== undefined ? { seed: opts.seed } : {}),
            ...(opts.maxTokens !== undefined ? { max_tokens: opts.maxTokens } : {}),
          }),
          signal: controller.signal,
        });
        if (!res.ok) throw await httpError('OpenAI', 'OPENAI_API_KEY', res);
        const parsed = ChatCompletionSchema.parse(await res.json());
        return parsed.choices[0]!.message.content ?? '';
      } catch (err) {
        if (isAbort(err)) throw new LlmTimeoutError('OpenAI', timeoutMs);
        throw err;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

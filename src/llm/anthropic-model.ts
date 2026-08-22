/**
 * `ChatModel` over the Anthropic Messages API (`POST /v1/messages`).
 *
 * Claude is not reachable through the `/chat/completions` shape — different
 * endpoint, `x-api-key` + `anthropic-version` headers instead of a bearer, a
 * REQUIRED `max_tokens`, and a content-BLOCK response rather than a single
 * string. Squeezing it into the OpenAI client would mean a pile of conditionals
 * in the hot path, so it gets its own small client with the same contract.
 *
 * Two deliberate choices worth knowing:
 *   - No `temperature` unless the caller asks: current Claude models reject
 *     sampling parameters outright (HTTP 400), so sending a "harmless" default
 *     would break the default model.
 *   - A roomy `max_tokens`: on current models thinking is on by default and
 *     shares that ceiling, so a stingy cap can return a truncated (or empty)
 *     verdict — which an oracle would read as "no violation".
 *
 * Keys live only in request headers and are never logged.
 */
import { z } from 'zod';
import type { ChatModel } from './model.js';
import { estimateUsd } from './pricing.js';
import { httpError, isAbort, LlmTimeoutError } from './http-error.js';

/** Wire version pin for the Messages API — sent on every request. */
export const ANTHROPIC_VERSION = '2023-06-01';

/** Current default judge/attacker model. */
export const DEFAULT_ANTHROPIC_MODEL = 'claude-opus-5';

export interface AnthropicModelOptions {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
  /** Required by the API; defaults high enough to leave room for thinking. */
  maxTokens?: number;
  system?: string;
  /** Only sent when set — current models 400 on sampling parameters. */
  temperature?: number;
  timeoutMs?: number;
  anthropicVersion?: string;
  fetchImpl?: typeof fetch;
}

const MessageSchema = z.object({
  content: z.array(z.object({ type: z.string(), text: z.string().optional() })),
  stop_reason: z.string().nullable().optional(),
});

export function anthropicModel(opts: AnthropicModelOptions = {}): ChatModel {
  const baseUrl = (opts.baseUrl ?? 'https://api.anthropic.com').replace(/\/+$/, '');
  const model = opts.model ?? DEFAULT_ANTHROPIC_MODEL;
  const maxTokens = opts.maxTokens ?? 8192;
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const doFetch = opts.fetchImpl ?? fetch;

  return {
    id: `anthropic:${model}`,

    estimateUsd: (prompt: string, completion: string) => estimateUsd(model, prompt, completion),

    async complete(prompt: string): Promise<string> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await doFetch(`${baseUrl}/v1/messages`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'anthropic-version': opts.anthropicVersion ?? ANTHROPIC_VERSION,
            ...(opts.apiKey ? { 'x-api-key': opts.apiKey } : {}),
          },
          body: JSON.stringify({
            model,
            max_tokens: maxTokens,
            messages: [{ role: 'user', content: prompt }],
            ...(opts.system !== undefined ? { system: opts.system } : {}),
            ...(opts.temperature !== undefined ? { temperature: opts.temperature } : {}),
          }),
          signal: controller.signal,
        });
        if (!res.ok) throw await httpError('Anthropic', 'ANTHROPIC_API_KEY', res);
        const parsed = MessageSchema.parse(await res.json());
        if (parsed.stop_reason === 'refusal') {
          // Surfaced, not swallowed: callers (the judge oracle) treat a thrown
          // judge as "unavailable" and keep their deterministic verdict.
          throw new Error(`Anthropic declined the request (stop_reason=refusal, model ${model})`);
        }
        // Text blocks only — thinking blocks carry no answer text.
        return parsed.content
          .filter((b) => b.type === 'text')
          .map((b) => b.text ?? '')
          .join('');
      } catch (err) {
        if (isAbort(err)) throw new LlmTimeoutError('Anthropic', timeoutMs);
        throw err;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

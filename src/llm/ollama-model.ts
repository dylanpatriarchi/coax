/**
 * Ollama-backed `ChatModel` — the default judge/attacker model, kept local so
 * Gauntlet has no cloud dependency out of the box. Wrap it in `CachingModel` +
 * `CallBudget` before handing it to an oracle. Never used by offline CI.
 */
import type { ChatModel } from './model.js';

export interface OllamaModelOptions {
  baseUrl?: string;
  model?: string;
  temperature?: number;
  seed?: number;
  timeoutMs?: number;
}

export function ollamaModel(opts: OllamaModelOptions = {}): ChatModel {
  const baseUrl = opts.baseUrl ?? 'http://localhost:11434';
  const model = opts.model ?? 'qwen3.5:0.8b';
  const temperature = opts.temperature ?? 0;
  const seed = opts.seed ?? 42;
  const timeoutMs = opts.timeoutMs ?? 60_000;

  return {
    id: `ollama:${model}`,
    async complete(prompt: string): Promise<string> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(`${baseUrl}/api/generate`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            model,
            prompt,
            stream: false,
            // Reasoning models (e.g. qwen3.x) otherwise emit an empty `response`
            // and put everything in `thinking`; disable that for direct answers.
            think: false,
            options: { temperature, seed },
          }),
          signal: controller.signal,
        });
        if (!res.ok) {
          throw new Error(`Ollama ${res.status}: ${await res.text()}`);
        }
        const json = (await res.json()) as { response?: string; thinking?: string };
        // Prefer the answer; fall back to thinking text if the model still routed
        // its output there despite think:false.
        return json.response && json.response.length > 0 ? json.response : json.thinking ?? '';
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

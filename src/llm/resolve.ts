/**
 * The ONE place COAX reads LLM configuration from the environment.
 *
 * Before this file, `.env.example` documented six variables and `src/` read
 * exactly one of them (`COAX_I_AM_AUTHORIZED`) — the judge oracle and the
 * adaptive attacker were hardwired to local Ollama and the cost caps were
 * decoration. Centralising the reads here means: secrets are touched in a single
 * auditable module (never logged, never re-read from a client), every live model
 * arrives already wrapped in `CachingModel` + `CallBudget`, and the offline kill
 * switch is enforced once instead of at six call sites.
 *
 * Two entry points, because "the attacker needs a model" and "a judge would be
 * nice" are different questions:
 *   - `resolveModel`      — give me the configured model, defaulting to local
 *                           Ollama when nothing is set (what the adaptive
 *                           attacker has always done).
 *   - `resolveJudgeModel` — give me a judge ONLY if the environment explicitly
 *                           configures one. Oracles are deterministic-first: an
 *                           unconfigured machine must keep the pattern fallback
 *                           rather than silently start dialling localhost.
 *
 * `COAX_OFFLINE=1` (what CI sets) is a hard kill switch: both return `null` and
 * no network client can be constructed at all.
 */
import { z } from 'zod';
import { CachingModel, CallBudget } from './model.js';
import type { ChatModel } from './model.js';
import { anthropicModel } from './anthropic-model.js';
import { openAIModel } from './openai-model.js';
import { ollamaModel } from './ollama-model.js';

export type LlmProvider = 'anthropic' | 'openai' | 'ollama' | 'none';

/** Truthy spellings accepted for boolean env flags (mirrors the authz gate). */
const TRUTHY = new Set(['true', '1', 'yes', 'on']);

const EnvSchema = z.object({
  COAX_OFFLINE: z.string().optional(),
  COAX_PROVIDER: z.enum(['anthropic', 'openai', 'ollama', 'none']).optional(),
  COAX_MODEL: z.string().min(1).optional(),
  COAX_MAX_LLM_CALLS: z.coerce.number().int().positive().optional(),
  COAX_MAX_USD: z.coerce.number().positive().optional(),
  COAX_LLM_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  ANTHROPIC_API_KEY: z.string().min(1).optional(),
  ANTHROPIC_BASE_URL: z.string().min(1).optional(),
  OPENAI_API_KEY: z.string().min(1).optional(),
  OPENAI_BASE_URL: z.string().min(1).optional(),
  OLLAMA_BASE_URL: z.string().min(1).optional(),
});

export type LlmEnvConfig = z.infer<typeof EnvSchema> & { offline: boolean };

export type EnvRecord = Record<string, string | undefined>;

/** Default call ceiling when `COAX_MAX_LLM_CALLS` is unset (matches .env.example). */
export const DEFAULT_MAX_LLM_CALLS = 200;

const KNOWN_KEYS = Object.keys(EnvSchema.shape);

/**
 * Validate the LLM-related variables. Blank values are treated as UNSET — a
 * `.env` copied from `.env.example` is full of `KEY=` lines and that must mean
 * "not configured", not "configured with an empty key". Anything else that is
 * malformed (`COAX_MAX_USD=abc`) fails loudly here rather than at spend time.
 */
export function readLlmEnv(env: EnvRecord = process.env): LlmEnvConfig {
  const raw: EnvRecord = {};
  for (const key of KNOWN_KEYS) {
    const value = env[key]?.trim();
    if (value !== undefined && value.length > 0) raw[key] = value;
  }

  const parsed = EnvSchema.safeParse(raw);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(env)'}: ${i.message}`)
      .join('; ');
    throw new Error(`Invalid COAX LLM configuration — ${details}`);
  }

  return { ...parsed.data, offline: TRUTHY.has((raw.COAX_OFFLINE ?? '').toLowerCase()) };
}

/** True when the environment says anything at all about which model to use. */
export function isLlmConfigured(cfg: LlmEnvConfig): boolean {
  return (
    cfg.COAX_PROVIDER !== undefined ||
    cfg.COAX_MODEL !== undefined ||
    cfg.ANTHROPIC_API_KEY !== undefined ||
    cfg.OPENAI_API_KEY !== undefined
  );
}

/** Guess the provider from a model id when `COAX_PROVIDER` is not explicit. */
export function providerForModel(modelId: string): LlmProvider | undefined {
  const id = modelId.toLowerCase();
  if (id.startsWith('claude') || id.startsWith('anthropic')) return 'anthropic';
  if (/^(gpt-|o[1-9]|text-|chatgpt)/.test(id)) return 'openai';
  // Ollama tags look like `qwen3.5:0.8b` / `llama3:8b`.
  if (id.includes(':')) return 'ollama';
  return undefined;
}

/** Provider selection: explicit wins, then the model id, then whichever key is present. */
export function selectProvider(cfg: LlmEnvConfig): LlmProvider {
  if (cfg.COAX_PROVIDER) return cfg.COAX_PROVIDER;
  const fromModel = cfg.COAX_MODEL ? providerForModel(cfg.COAX_MODEL) : undefined;
  if (fromModel) return fromModel;
  if (cfg.ANTHROPIC_API_KEY) return 'anthropic';
  if (cfg.OPENAI_API_KEY) return 'openai';
  return 'ollama';
}

function buildClient(provider: LlmProvider, cfg: LlmEnvConfig): ChatModel | null {
  // Defence in depth: even a mis-wired caller cannot open a socket while the
  // kill switch is on.
  if (cfg.offline) {
    throw new Error('COAX_OFFLINE is set — refusing to construct a network LLM client');
  }
  const timeoutMs = cfg.COAX_LLM_TIMEOUT_MS;

  switch (provider) {
    case 'none':
      return null;

    case 'anthropic': {
      if (!cfg.ANTHROPIC_API_KEY) {
        throw new Error(
          'Anthropic provider selected but ANTHROPIC_API_KEY is not set (see .env.example)',
        );
      }
      return anthropicModel({
        apiKey: cfg.ANTHROPIC_API_KEY,
        ...(cfg.ANTHROPIC_BASE_URL !== undefined ? { baseUrl: cfg.ANTHROPIC_BASE_URL } : {}),
        ...(cfg.COAX_MODEL !== undefined ? { model: cfg.COAX_MODEL } : {}),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
    }

    case 'openai': {
      const baseUrl = cfg.OPENAI_BASE_URL;
      // A self-hosted endpoint (vLLM, llama.cpp, Ollama's /v1) needs no key;
      // OpenAI's own API always does, so catch the missing key before the 401.
      const isCloud = baseUrl === undefined || /(^|\.)api\.openai\.com/i.test(baseUrl);
      if (isCloud && !cfg.OPENAI_API_KEY) {
        throw new Error(
          'OpenAI provider selected but OPENAI_API_KEY is not set (see .env.example). ' +
            'Set OPENAI_BASE_URL to a local endpoint if you meant to use a self-hosted model.',
        );
      }
      return openAIModel({
        ...(cfg.OPENAI_API_KEY !== undefined ? { apiKey: cfg.OPENAI_API_KEY } : {}),
        ...(baseUrl !== undefined ? { baseUrl } : {}),
        ...(cfg.COAX_MODEL !== undefined ? { model: cfg.COAX_MODEL } : {}),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
    }

    case 'ollama':
      return ollamaModel({
        ...(cfg.OLLAMA_BASE_URL !== undefined ? { baseUrl: cfg.OLLAMA_BASE_URL } : {}),
        ...(cfg.COAX_MODEL !== undefined ? { model: cfg.COAX_MODEL } : {}),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
  }
}

/** The cost/rate guard every resolved model is wrapped in. */
export function budgetFor(cfg: LlmEnvConfig): CallBudget {
  return new CallBudget(
    cfg.COAX_MAX_LLM_CALLS ?? DEFAULT_MAX_LLM_CALLS,
    cfg.COAX_MAX_USD ?? Number.POSITIVE_INFINITY,
  );
}

/**
 * Build the configured model, budgeted and cached. Returns `null` when
 * `COAX_OFFLINE` is set or the provider is explicitly `none`; falls back to
 * local Ollama when nothing is configured.
 */
export function resolveModel(env: EnvRecord = process.env): ChatModel | null {
  const cfg = readLlmEnv(env);
  if (cfg.offline) return null;
  const inner = buildClient(selectProvider(cfg), cfg);
  return inner ? new CachingModel(inner, budgetFor(cfg)) : null;
}

/**
 * Same, but for the LLM-judge oracles: returns `null` unless the environment
 * explicitly names a provider/model/key. Judges are an opt-in refinement of the
 * deterministic oracles, so "nothing configured" must mean "no judge" — not "go
 * looking for a model on localhost".
 */
export function resolveJudgeModel(env: EnvRecord = process.env): ChatModel | null {
  const cfg = readLlmEnv(env);
  if (cfg.offline || !isLlmConfigured(cfg)) return null;
  return resolveModel(env);
}

let sharedJudge: ChatModel | null | undefined;

/**
 * Process-wide judge, resolved on first use and shared by every oracle so they
 * share one cache and one budget. Lazy on purpose: importing an oracle must not
 * read the environment or build a client.
 */
export function defaultJudgeModel(env: EnvRecord = process.env): ChatModel | null {
  if (sharedJudge === undefined) sharedJudge = resolveJudgeModel(env);
  return sharedJudge;
}

/** Test seam: forget the memoised judge so a new environment takes effect. */
export function resetDefaultJudgeModel(): void {
  sharedJudge = undefined;
}

/**
 * The scan runner — the connective tissue between attacks, a target, and oracles.
 *
 * For each generated payload it (optionally) resets the target, stages any
 * indirect content, sends the message, then runs every oracle over the response.
 * It emits one `Attempt` record per payload. Aggregation into ASR/severity/
 * taxonomy scores and the report is milestone 7; this just produces the raw,
 * reproducible evidence.
 */
import { generatePayloads } from '../attacks/index.js';
import { supportsInjection } from './target.js';
import type { AttackModule, AttackPayload } from './attack.js';
import type { Oracle, OracleVerdict } from './oracle.js';
import { makeRng } from './rng.js';
import type { AgentResponse, TargetAdapter } from './target.js';

export interface Attempt {
  payload: AttackPayload;
  response: AgentResponse;
  verdicts: OracleVerdict[];
  /** True if any oracle flagged success. */
  success: boolean;
}

export interface ScanOptions {
  target: TargetAdapter;
  modules: readonly AttackModule[];
  oracles: readonly Oracle[];
  seed: number;
  canary?: string;
  maxPayloads?: number;
}

export interface ScanResult {
  seed: number;
  target: string;
  attempts: Attempt[];
}

async function runOne(
  opts: ScanOptions,
  payload: AttackPayload,
  forbiddenTools: string[],
): Promise<Attempt> {
  const { target, oracles, canary } = opts;

  if (target.reset) await target.reset();
  if (payload.inject && supportsInjection(target)) {
    await target.injectContent(payload.inject);
  }

  const response: AgentResponse = await target.sendMessage({ message: payload.message });

  const verdicts: OracleVerdict[] = [];
  for (const oracle of oracles) {
    verdicts.push(
      await oracle.evaluate({
        payload,
        response,
        ...(canary !== undefined ? { canary } : {}),
        forbiddenTools,
      }),
    );
  }

  return { payload, response, verdicts, success: verdicts.some((v) => v.success) };
}

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const tools = opts.target.describeTools ? await opts.target.describeTools() : [];
  const forbidden = tools.filter((t) => t.forbidden).map((t) => t.name);

  const ctx = {
    rng: makeRng(opts.seed),
    ...(opts.canary !== undefined ? { canary: opts.canary } : {}),
    tools,
    ...(opts.maxPayloads !== undefined ? { maxPayloads: opts.maxPayloads } : {}),
  };
  const payloads = generatePayloads(opts.modules, ctx);

  // Sequential by default: keeps ordering deterministic and respects target rate
  // limits. (Bounded concurrency is a later, opt-in optimisation.)
  const attempts: Attempt[] = [];
  for (const payload of payloads) {
    attempts.push(await runOne(opts, payload, forbidden));
  }

  return { seed: opts.seed, target: opts.target.name, attempts };
}

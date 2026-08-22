/**
 * The scan runner — the connective tissue between attacks, a target, and oracles.
 *
 * For each generated payload it (optionally) resets the target, stages any
 * indirect content, sends the message, then runs every oracle over the response.
 * It emits one `Attempt` record per payload. Aggregation into ASR/severity/
 * taxonomy scores lives in `report/scoring.ts`; this just produces the raw,
 * reproducible evidence.
 *
 * Things the runner is careful about beyond "send and check":
 *
 *  - REPEATED TRIALS. Sending each payload once against a stochastic target
 *    produces an ASR with unknown variance — two runs of the same suite disagree
 *    and neither number is defensible. `trials` sends each payload N times and
 *    records hits/trials, which is what lets the scorer attach a confidence
 *    interval. Each trial derives its own child RNG stream from the scan seed,
 *    so a multi-trial scan is as reproducible as a single-trial one. Default 1:
 *    existing behaviour is bit-for-bit unchanged.
 *
 *  - ON-TARGET vs. COLLATERAL. `verdicts.some(v => v.success)` treats every
 *    oracle as equally meaningful for every payload, so a code-execution payload
 *    that trips only the trust oracle scores as a code-execution success. When a
 *    payload declares `expectedOracles`, only those oracles count toward its
 *    headline result; anything else fired is recorded separately as collateral.
 *    Payloads that declare nothing keep the old any-oracle semantics.
 *
 *  - REPRODUCIBILITY. Payloads come from `planScan`, which is pure given
 *    (seed, modules, context). `--dry-run` prints exactly that list, so what a
 *    user previews is what the runner sends.
 *
 *  - ORDER. Attempts are always returned in payload order, never completion
 *    order, so a concurrent run scores identically to a sequential one.
 *
 *  - ISOLATION. `reset -> inject -> send` is one stateful transaction against a
 *    target, and repeated trials of one payload belong to the same attempt.
 *    Running several in parallel on ONE adapter would interleave them, so
 *    concurrency > 1 requires `createTarget` to hand each worker its own
 *    adapter instance; without it the runner stays sequential rather than
 *    silently producing corrupted evidence. A worker is also wrapped in lane
 *    0's defense stack when the factory hands back a bare adapter, so every
 *    lane measures the same system.
 */
import { generatePayloads } from '../attacks/index.js';
import { supportsInjection } from './target.js';
import type { AttackModule, AttackPayload } from './attack.js';
import type { DefenseTrace } from './defense.js';
import { isDefendedTarget, withDefenses } from './defense.js';
import type { Oracle, OracleVerdict } from './oracle.js';
import { makeRng } from './rng.js';
import { withRetry } from './retry.js';
import type { RetryOptions } from './retry.js';
import type { AgentResponse, TargetAdapter, ToolSpec } from './target.js';

/** One send of one payload. */
export interface TrialResult {
  /** 0-based trial index within the attempt. */
  index: number;
  response: AgentResponse;
  verdicts: OracleVerdict[];
  /** An expected oracle fired — or, when none is declared, any oracle did. */
  onTarget: boolean;
  /** An oracle fired, but not one the payload claimed. Never both with onTarget. */
  collateral: boolean;
  /** Present only when the target is wrapped in a defense stack. */
  defense?: DefenseTrace;
}

export interface Attempt {
  payload: AttackPayload;
  /** Representative trial: the first on-target success, else the first trial. */
  response: AgentResponse;
  verdicts: OracleVerdict[];
  /**
   * True if at least one trial was an ON-TARGET success. Identical to the old
   * any-oracle semantics for payloads that declare no `expectedOracles`.
   */
  success: boolean;
  /** True if a trial fired oracles the payload never claimed, and none it did. */
  collateral: boolean;
  /** How many times the payload was sent. */
  trials: number;
  /** Trials that were an on-target success. */
  hits: number;
  /** Trials whose only firing oracles were unexpected ones. */
  collateralHits: number;
  /** Trials a defense refused outright (no agent response at all). */
  blocked: number;
  /** Per-trial detail. Present for runner-produced attempts. */
  trialResults?: TrialResult[];
}

export interface ScanOptions {
  target: TargetAdapter;
  modules: readonly AttackModule[];
  oracles: readonly Oracle[];
  seed: number;
  canary?: string;
  /**
   * Budget cap. Passed to the modules as a hint AND enforced afterwards, per
   * module, in `planScan`: modules interpret the hint differently (some cap per
   * variant, some per tool) and `--max-payloads 2` has to mean two payloads.
   */
  maxPayloads?: number;
  /**
   * How many times to send each payload. Default 1. Values above 1 are what make
   * the reported ASR carry a meaningful confidence interval against a
   * non-deterministic target.
   */
  trials?: number;
  /**
   * Post-generation payload filter (the CLI's `--surface`). Applied after
   * generation so module ids/indices — and therefore payload ids — do not shift
   * when a surface is filtered out.
   */
  payloadFilter?: (payload: AttackPayload) => boolean;
  /** Attempts in flight. Default 1: today's deterministic sequential behaviour. */
  concurrency?: number;
  /**
   * Builds an isolated target per worker; required for real parallelism. It must
   * apply the same wrapping as `target` (defenses included), or the workers
   * would scan a different agent than lane 0.
   */
  createTarget?: () => TargetAdapter | Promise<TargetAdapter>;
  /** Bounded retry for transient target failures (timeout / 429 / 5xx). */
  retry?: RetryOptions;
  /**
   * Called as each attempt completes, for a terminal progress line. Purely
   * informational: it fires in COMPLETION order (which a concurrent run does not
   * fix), carries nothing the report reads, and must never influence the result.
   */
  onProgress?: (info: { completed: number; total: number; payload: AttackPayload }) => void;
}

export interface ScanResult {
  seed: number;
  target: string;
  /** Trials per payload used for this scan. */
  trials: number;
  attempts: Attempt[];
}

/**
 * Split fired oracles into on-target and collateral for one payload.
 *
 * With no declared expectation every oracle counts, which is exactly the
 * pre-existing behaviour — so nothing regresses for third-party modules.
 */
export function classifyVerdicts(
  payload: Pick<AttackPayload, 'expectedOracles'>,
  verdicts: readonly OracleVerdict[],
): { onTarget: boolean; collateral: boolean } {
  const fired = verdicts.filter((v) => v.success);
  const expected = payload.expectedOracles;
  if (expected === undefined || expected.length === 0) {
    return { onTarget: fired.length > 0, collateral: false };
  }
  const wanted = new Set(expected);
  const onTarget = fired.some((v) => wanted.has(v.oracleId));
  return { onTarget, collateral: !onTarget && fired.length > 0 };
}

async function runTrial(
  opts: ScanOptions,
  target: TargetAdapter,
  payload: AttackPayload,
  forbiddenTools: string[],
  tools: ToolSpec[],
  index: number,
  conversationId: string | undefined,
): Promise<TrialResult> {
  const { oracles, canary } = opts;

  // The whole staging transaction retries together: replaying only the send
  // would deliver a payload whose indirect content was never staged.
  const response: AgentResponse = await withRetry(async () => {
    if (target.reset) await target.reset();
    if (payload.inject && supportsInjection(target)) {
      await target.injectContent(payload.inject);
    }
    return target.sendMessage({
      message: payload.message,
      ...(conversationId !== undefined ? { conversationId } : {}),
    });
  }, opts.retry ?? {});

  const verdicts: OracleVerdict[] = [];
  for (const oracle of oracles) {
    verdicts.push(
      await oracle.evaluate({
        payload,
        response,
        ...(canary !== undefined ? { canary } : {}),
        forbiddenTools,
        tools,
      }),
    );
  }

  const { onTarget, collateral } = classifyVerdicts(payload, verdicts);

  // A blocked turn is evidence, not an absence: record what the control did so
  // the attempt scores as defended rather than merely unsuccessful.
  let defense: DefenseTrace | undefined;
  if (isDefendedTarget(target)) {
    const events = target.consumeEvents();
    defense = {
      blocked: events.some((e) => e.action === 'blocked' && e.stage !== 'ingest'),
      events,
    };
  }

  return {
    index,
    response,
    verdicts,
    onTarget,
    collateral,
    ...(defense !== undefined ? { defense } : {}),
  };
}

async function runOne(
  opts: ScanOptions,
  target: TargetAdapter,
  payload: AttackPayload,
  forbiddenTools: string[],
  tools: ToolSpec[],
  trials: number,
  seed: number,
): Promise<Attempt> {
  const trialResults: TrialResult[] = [];
  for (let i = 0; i < trials; i++) {
    // Each trial gets its own child stream off the scan seed. With trials === 1
    // no conversation id is set at all, so the single-trial path is byte-for-byte
    // what it was before repeated trials existed. Deriving from (seed, payload
    // id, trial index) — never from a running counter — is also what keeps the
    // ids stable when the attempts are spread across concurrent workers.
    const conversationId =
      trials > 1
        ? `trial-${makeRng(seed).derive(`${payload.id}#trial:${i}`).int(0, 0xffffff).toString(16)}`
        : undefined;
    trialResults.push(
      await runTrial(opts, target, payload, forbiddenTools, tools, i, conversationId),
    );
  }

  const hits = trialResults.filter((t) => t.onTarget).length;
  const collateralHits = trialResults.filter((t) => t.collateral).length;
  const blocked = trialResults.filter((t) => t.defense?.blocked === true).length;
  const representative = trialResults.find((t) => t.onTarget) ?? (trialResults[0] as TrialResult);

  return {
    payload,
    response: representative.response,
    verdicts: representative.verdicts,
    success: hits > 0,
    collateral: hits === 0 && collateralHits > 0,
    trials,
    hits,
    collateralHits,
    blocked,
    trialResults,
  };
}

/**
 * The exact payload set a scan would send, in order. Pure apart from reading the
 * target's tool manifest — no attack is delivered, which is what makes
 * `coax scan --dry-run` free.
 */
export async function planScan(opts: ScanOptions): Promise<AttackPayload[]> {
  const tools = opts.target.describeTools ? await opts.target.describeTools() : [];
  const ctx = {
    rng: makeRng(opts.seed),
    ...(opts.canary !== undefined ? { canary: opts.canary } : {}),
    tools,
    ...(opts.maxPayloads !== undefined ? { maxPayloads: opts.maxPayloads } : {}),
  };
  const generated = generatePayloads(opts.modules, ctx);
  const filtered = opts.payloadFilter ? generated.filter(opts.payloadFilter) : generated;
  if (opts.maxPayloads === undefined) return filtered;

  // Enforce the cap per module, keeping generation order so the kept payloads
  // are the same ones every run.
  const perModule = new Map<string, number>();
  return filtered.filter((p) => {
    const used = perModule.get(p.moduleId) ?? 0;
    if (used >= (opts.maxPayloads as number)) return false;
    perModule.set(p.moduleId, used + 1);
    return true;
  });
}

export async function runScan(opts: ScanOptions): Promise<ScanResult> {
  const trials = Math.max(1, Math.trunc(opts.trials ?? 1));
  const tools = opts.target.describeTools ? await opts.target.describeTools() : [];
  const forbidden = tools.filter((t) => t.forbidden).map((t) => t.name);
  const payloads = await planScan(opts);

  // One adapter per worker, or one shared adapter when running sequentially.
  const requested = Math.max(1, opts.concurrency ?? 1);
  const lanes = opts.createTarget ? Math.min(requested, payloads.length || 1) : 1;
  const workers: TargetAdapter[] = [opts.target];
  const createTarget = opts.createTarget;
  // Every lane must be the SAME system under test as lane 0. When lane 0 is
  // defended and the factory yields a bare adapter — which is exactly what
  // happens when `compareDefenses` re-runs a scan behind a stack — the worker is
  // wrapped in the identical defenses, or half the scan would silently measure
  // an undefended target.
  const lane0 = opts.target;
  const matchLane0 = (t: TargetAdapter): TargetAdapter =>
    isDefendedTarget(lane0) && !isDefendedTarget(t) ? withDefenses(t, lane0.defenses) : t;
  for (let i = 1; i < lanes && createTarget; i += 1) {
    workers.push(matchLane0(await createTarget()));
  }

  // Drop anything a previous caller left in a defended target's event log, so
  // each attempt's trace contains only its own events.
  for (const worker of workers) {
    if (isDefendedTarget(worker)) worker.consumeEvents();
  }

  // Index-addressed results: workers race, the array stays in payload order.
  const attempts = new Array<Attempt | undefined>(payloads.length);
  let next = 0;
  let completed = 0;
  await Promise.all(
    workers.map(async (worker) => {
      for (;;) {
        const index = next;
        next += 1;
        const payload = payloads[index];
        if (payload === undefined) return;
        attempts[index] = await runOne(opts, worker, payload, forbidden, tools, trials, opts.seed);
        completed += 1;
        opts.onProgress?.({ completed, total: payloads.length, payload });
      }
    }),
  );

  return {
    seed: opts.seed,
    target: opts.target.name,
    trials,
    attempts: attempts.filter((a): a is Attempt => a !== undefined),
  };
}

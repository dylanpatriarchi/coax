/**
 * `coax scan` — resolve a target, run the selected attacks, score, gate.
 *
 * WHY this file is the shape it is: everything the scan can be told to do
 * arrives as one already-validated `ScanArgs`, and the whole run is assembled in
 * ONE place (`runScanCommand`) rather than being spread across flag lookups.
 * That is what keeps the command readable at ~200 lines while covering
 * selection, the adaptive attacker, concurrency, JSON output, baselines and the
 * exit-code policy — and it is why a defense layer or repeated trials can be
 * folded in later by adding options to the same builder instead of a rewrite.
 *
 * Two invariants worth stating out loud:
 *   - The responsible-use gate runs BEFORE anything touches the target, on every
 *     path (dry-run included, so `--dry-run` can never be a way to poke a remote
 *     endpoint by accident).
 *   - Attempts are sorted by payload id before scoring. Concurrency, scenarios
 *     and the adaptive loop all feed the same stream, and the report must not
 *     depend on which of them finished first.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createMockAgent, MockConfigSchema } from '../../adapters/mock.js';
import { adaptiveAttempts, runAdaptive } from '../../attacks/adaptive-runner.js';
import { createAttackRegistry } from '../../attacks/index.js';
import { checkAuthorization } from '../../core/authorization.js';
import type { Oracle } from '../../core/oracle.js';
import { planScan, runScan } from '../../core/runner.js';
import type { Attempt } from '../../core/runner.js';
import type { TargetAdapter } from '../../core/target.js';
import { resolveModel } from '../../llm/resolve.js';
import { createOracleRegistry } from '../../oracles/index.js';
import { runFalsePositiveSuite } from '../../oracles/false-positive.js';
import { renderHtml } from '../../report/html.js';
import { renderMarkdown } from '../../report/markdown.js';
import { scoreScan } from '../../report/scoring.js';
import type { ScanReport } from '../../report/scoring.js';
import { runUtilitySuite } from '../../report/utility.js';
import { scenarioAttempts } from '../../scenarios/index.js';
import { CliError } from '../args.js';
import type { ScanArgs } from '../args.js';
import { diffReports, loadBaseline, renderDiff } from '../baseline.js';
import type { BaselineDiff } from '../baseline.js';
import { EXIT_OK, EXIT_UNAUTHORIZED } from '../exit-codes.js';
import { humanIo } from '../io.js';
import type { Io } from '../io.js';
import { canonicalJson } from '../json.js';
import { evaluatePolicy } from '../policy.js';
import { selectModules, surfaceFilter } from '../select.js';
import { renderScanSummary } from '../summary.js';
import { loadTarget } from '../load-target.js';

/** Everything the run needs about "what am I scanning", resolved once. */
interface ResolvedTarget {
  target: TargetAdapter;
  canary?: string;
  /** What the responsible-use gate judges. */
  gateTarget: string;
  /** Isolated instances for concurrent workers, when the target can make them. */
  createTarget?: () => Promise<TargetAdapter>;
  /** True when the user supplied their own module (disables the mock-only suites). */
  userSupplied: boolean;
}

async function resolveTarget(args: ScanArgs): Promise<ResolvedTarget> {
  if (args.target !== undefined) {
    const loaded = await loadTarget(args.target);
    return {
      target: loaded.target,
      ...(loaded.canary !== undefined ? { canary: loaded.canary } : {}),
      gateTarget: loaded.endpoint ?? args.target,
      ...(loaded.createTarget !== undefined ? { createTarget: loaded.createTarget } : {}),
      userSupplied: true,
    };
  }
  return {
    target: createMockAgent(),
    canary: MockConfigSchema.parse({}).canary,
    gateTarget: 'mock',
    createTarget: async () => createMockAgent(),
    userSupplied: false,
  };
}

/** Assemble the `runScan` options — the one place flags become library options. */
function scanOptions(args: ScanArgs, resolved: ResolvedTarget, io: Io) {
  const modules = selectModules(createAttackRegistry().list(), {
    ...(args.only !== undefined ? { only: args.only } : {}),
    ...(args.exclude !== undefined ? { exclude: args.exclude } : {}),
  });
  const filter = surfaceFilter(args.surface);

  return {
    target: resolved.target,
    modules,
    oracles: createOracleRegistry().list(),
    seed: args.seed,
    ...(resolved.canary !== undefined ? { canary: resolved.canary } : {}),
    ...(args.maxPayloads !== undefined ? { maxPayloads: args.maxPayloads } : {}),
    ...(filter !== undefined ? { payloadFilter: filter } : {}),
    concurrency: args.concurrency,
    ...(resolved.createTarget !== undefined ? { createTarget: resolved.createTarget } : {}),
    retry: {
      retries: args.retries,
      onRetry: ({ attempt, delayMs }: { attempt: number; delayMs: number }) => {
        io.err(`  retrying after transient target failure (attempt ${attempt}, ${delayMs}ms)`);
      },
    },
  };
}

async function dryRun(args: ScanArgs, resolved: ResolvedTarget, io: Io): Promise<number> {
  const payloads = await planScan(scanOptions(args, resolved, io));
  if (args.json) {
    io.out(canonicalJson({ seed: args.seed, target: resolved.target.name, payloads }).trimEnd());
    return EXIT_OK;
  }
  io.out(`coax scan --dry-run — target: ${resolved.target.name}  seed: ${args.seed}`);
  io.out(`  ${payloads.length} payload(s) would be sent; the target is not contacted.\n`);
  const idWidth = Math.max(...payloads.map((p) => p.id.length), 10);
  const famWidth = Math.max(...payloads.map((p) => p.family.length), 6);
  for (const p of payloads) {
    io.out(
      `  ${p.id.padEnd(idWidth + 2)}${p.family.padEnd(famWidth + 2)}` +
        `${p.surface.padEnd(12)}${p.severity.padEnd(10)}${p.technique}`,
    );
  }
  return EXIT_OK;
}

/** The closed-loop attacker, folded into the same attempt stream as the suite. */
async function adaptiveRun(
  args: ScanArgs,
  resolved: ResolvedTarget,
  oracles: readonly Oracle[],
): Promise<Attempt[]> {
  if (args.goal === undefined) throw new CliError('--adaptive requires --goal.');
  const model = resolveModel();
  if (!model) {
    throw new CliError(
      '--adaptive: no attacker model is available — COAX_OFFLINE is set (or ' +
        'COAX_PROVIDER=none). Unset it and configure a provider (see .env.example) ' +
        'to run the adaptive loop.',
    );
  }
  const tools = resolved.target.describeTools ? await resolved.target.describeTools() : [];
  const result = await runAdaptive({
    target: resolved.target,
    oracles,
    goal: args.goal,
    ...(resolved.canary !== undefined ? { canary: resolved.canary } : {}),
    forbiddenTools: tools.filter((t) => t.forbidden).map((t) => t.name),
    seed: args.seed,
    maxIterations: args.maxIterations,
    ...(args.maxModelCalls !== undefined ? { maxModelCalls: args.maxModelCalls } : {}),
    persist: args.persist,
    model,
  });
  return adaptiveAttempts(result);
}

function writeReports(outDir: string, report: ScanReport, io: Io): void {
  mkdirSync(outDir, { recursive: true });
  // The ONLY wall-clock in the whole pipeline, and it stays a render-time field:
  // report.json must diff cleanly against a baseline taken yesterday.
  const generatedAt = new Date().toISOString();
  writeFileSync(join(outDir, 'report.md'), renderMarkdown(report, { generatedAt }));
  writeFileSync(join(outDir, 'report.html'), renderHtml(report, { generatedAt }));
  writeFileSync(join(outDir, 'report.json'), canonicalJson(report));
  io.out(`\n  report written to ${join(outDir, 'report.md')}, report.html and report.json`);
}

export async function runScanCommand(args: ScanArgs, io: Io): Promise<number> {
  const human = humanIo(io, args.json);
  const resolved = await resolveTarget(args);

  const gate = checkAuthorization({
    target: resolved.gateTarget,
    flag: args.iAmAuthorized,
    env: process.env.COAX_I_AM_AUTHORIZED,
  });
  if (!gate.allowed) {
    io.err(gate.reason);
    return EXIT_UNAUTHORIZED;
  }

  if (args.dryRun) return dryRun(args, resolved, io);

  const options = scanOptions(args, resolved, human);
  const oracles = options.oracles;
  const result = await runScan(options);

  // Measure utility on a PRISTINE target (a fresh mock, or the user's module) so
  // any state the scan left behind can't skew the benign/under-attack numbers.
  const utilityTarget = resolved.userSupplied ? resolved.target : createMockAgent();
  const utilTools = utilityTarget.describeTools ? await utilityTarget.describeTools() : [];
  const utilForbidden = utilTools.filter((t) => t.forbidden).map((t) => t.name);
  const canaryOpt = resolved.canary !== undefined ? { canary: resolved.canary } : {};

  // Scenarios, utility and the false-positive suite are independent of one
  // another (the scan result is already computed), so overlap them.
  const [scenAttempts, utility, fp, adaptive] = await Promise.all([
    // Multi-step scenarios run against their own built-in vulnerable targets, so
    // they only apply to the default mock.
    args.scenarios && !resolved.userSupplied
      ? scenarioAttempts({ oracles, seed: args.seed, ...canaryOpt })
      : Promise.resolve([]),
    args.utility
      ? runUtilitySuite(utilityTarget, oracles, { ...canaryOpt, forbiddenTools: utilForbidden })
      : Promise.resolve(undefined),
    args.fp ? runFalsePositiveSuite(oracles, canaryOpt) : Promise.resolve(undefined),
    args.adaptive ? adaptiveRun(args, resolved, oracles) : Promise.resolve([]),
  ]);

  // Payload-id order, never completion order: the report must be identical
  // whatever the concurrency was.
  const attempts = [...result.attempts, ...scenAttempts, ...adaptive].sort((a, b) =>
    a.payload.id.localeCompare(b.payload.id),
  );
  const report = scoreScan(
    { ...result, attempts },
    {
      ...(fp !== undefined ? { falsePositive: fp } : {}),
      ...(utility !== undefined ? { utility } : {}),
    },
  );

  let diff: BaselineDiff | undefined;
  if (args.baseline !== undefined) {
    diff = diffReports(loadBaseline(args.baseline), report);
  }

  if (args.json) {
    io.out(canonicalJson(report).trimEnd());
  } else {
    renderScanSummary(report, human);
  }

  if (diff) {
    human.out('\n  regression vs. baseline:');
    for (const line of renderDiff(diff)) human.out(line);
  }

  if (args.out !== undefined) writeReports(args.out, report, human);
  else if (!args.json) human.out('\n  (pass --out <dir> for the full Markdown/HTML/JSON report)');

  const verdict = evaluatePolicy(
    report,
    {
      ...(args.failOnSeverity !== undefined ? { failOnSeverity: args.failOnSeverity } : {}),
      ...(args.maxAsr !== undefined ? { maxAsr: args.maxAsr } : {}),
      ...(args.maxWeightedAsr !== undefined ? { maxWeightedAsr: args.maxWeightedAsr } : {}),
      failOnRegression: args.failOnRegression,
    },
    diff,
  );
  human.out(`\n${verdict.line}`);
  return verdict.exitCode;
}

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
import { withDefenses } from '../../core/defense.js';
import type { Defense } from '../../core/defense.js';
import type { Oracle } from '../../core/oracle.js';
import { planScan, runScan } from '../../core/runner.js';
import type { Attempt, ScanResult } from '../../core/runner.js';
import type { TargetAdapter } from '../../core/target.js';
import { resolveModel } from '../../llm/resolve.js';
import { createOracleRegistry } from '../../oracles/index.js';
import { runFalsePositiveSuite } from '../../oracles/false-positive.js';
import { compareDefenses } from '../../report/defense-comparison.js';
import type { DefenseComparison } from '../../report/defense-comparison.js';
import { renderHtml } from '../../report/html.js';
import { renderMarkdown } from '../../report/markdown.js';
import { scoreScan } from '../../report/scoring.js';
import type { ScanReport } from '../../report/scoring.js';
import { runUtilitySuite } from '../../report/utility.js';
import type { UtilityOptions, UtilityReport } from '../../report/utility.js';
import { scenarioAttempts, scenarioComparisonSource } from '../../scenarios/index.js';
import { CliError } from '../args.js';
import type { ScanArgs } from '../args.js';
import { diffReports, loadBaseline, renderDiff } from '../baseline.js';
import type { BaselineDiff } from '../baseline.js';
import { EXIT_OK, EXIT_UNAUTHORIZED } from '../exit-codes.js';
import { humanIo } from '../io.js';
import type { Io } from '../io.js';
import { canonicalJson } from '../json.js';
import { evaluatePolicy } from '../policy.js';
import { selectDefenses, selectModules, surfaceFilter } from '../select.js';
import { renderDefenseComparison, renderScanSummary } from '../summary.js';
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
    trials: args.trials,
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

async function dryRun(
  args: ScanArgs,
  resolved: ResolvedTarget,
  defenses: readonly Defense[],
  io: Io,
): Promise<number> {
  const payloads = await planScan(scanOptions(args, resolved, io));
  if (args.json) {
    io.out(
      canonicalJson({
        seed: args.seed,
        target: resolved.target.name,
        trials: args.trials,
        defenses: defenses.map((d) => d.id),
        payloads,
      }).trimEnd(),
    );
    return EXIT_OK;
  }
  io.out(`coax scan --dry-run — target: ${resolved.target.name}  seed: ${args.seed}`);
  const sends = payloads.length * args.trials;
  io.out(
    `  ${payloads.length} payload(s) would be sent${args.trials > 1 ? ` x ${args.trials} trials = ${sends} sends` : ''}; ` +
      'the target is not contacted.',
  );
  if (defenses.length > 0) {
    // Defenses do not change WHAT is sent, only what survives — say so rather
    // than letting a --dry-run --defense run look like it previewed the stack.
    io.out(
      `  defenses (${defenses.map((d) => d.id).join(', ')}) filter delivery, not generation: ` +
        'the payload set is the same.',
    );
  }
  io.out('');
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
  target: TargetAdapter,
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
  const tools = target.describeTools ? await target.describeTools() : [];
  const result = await runAdaptive({
    target,
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

  // Resolved before the dry-run branch so a typo in --defense is caught by the
  // cheapest command, not only by the expensive one.
  const scanTools = resolved.target.describeTools ? await resolved.target.describeTools() : [];
  const defenses: Defense[] =
    args.defense !== undefined
      ? selectDefenses(args.defense, {
          ...(resolved.canary !== undefined ? { canary: resolved.canary } : {}),
          forbiddenTools: scanTools.filter((t) => t.forbidden).map((t) => t.name),
        })
      : [];

  if (args.dryRun) return dryRun(args, resolved, defenses, io);

  const options = scanOptions(args, resolved, human);
  const oracles = options.oracles;

  // Measure utility on a PRISTINE target (a fresh mock, or the user's module) so
  // any state the scan left behind can't skew the benign/under-attack numbers.
  const makeUtilityTarget = (): TargetAdapter =>
    resolved.userSupplied ? resolved.target : createMockAgent();
  const utilityProbe = makeUtilityTarget();
  const utilTools = utilityProbe.describeTools ? await utilityProbe.describeTools() : [];
  const utilForbidden = utilTools.filter((t) => t.forbidden).map((t) => t.name);
  const canaryOpt = resolved.canary !== undefined ? { canary: resolved.canary } : {};
  const utilityOpts: UtilityOptions = { ...canaryOpt, forbiddenTools: utilForbidden };
  // Multi-step scenarios run against their own built-in vulnerable targets, so
  // they only apply to the default mock.
  const withScenarios = args.scenarios && !resolved.userSupplied;
  const scenarioOpts = { oracles, seed: args.seed, ...canaryOpt };

  let result: ScanResult;
  let scenAttempts: Attempt[];
  let utility: UtilityReport | undefined;
  let comparison: DefenseComparison | undefined;
  let attackedTarget = resolved.target;

  if (defenses.length > 0) {
    // With controls in place the interesting number is the DELTA, so the suite
    // runs twice from one seed and the report carries both columns. The defended
    // run is the one that becomes the report: it describes the system as
    // configured, and the thresholds gate it.
    const compared = await compareDefenses({
      ...options,
      defenses,
      ...(withScenarios ? { extraAttempts: scenarioComparisonSource(scenarioOpts) } : {}),
      utility: args.utility ? utilityOpts : false,
      utilityTarget: makeUtilityTarget,
    });
    result = compared.defended;
    scenAttempts = compared.defendedExtra;
    utility = compared.comparison.utility?.defended;
    comparison = compared.comparison;
    attackedTarget = withDefenses(resolved.target, defenses);
  } else {
    result = await runScan(options);
    // Scenarios and the utility suite are independent of one another (the scan
    // result is already computed), so overlap them.
    const [scen, util] = await Promise.all([
      withScenarios ? scenarioAttempts(scenarioOpts) : Promise.resolve([]),
      args.utility
        ? runUtilitySuite(makeUtilityTarget(), oracles, utilityOpts)
        : Promise.resolve(undefined),
    ]);
    scenAttempts = scen;
    utility = util;
  }

  const [fp, adaptive] = await Promise.all([
    args.fp ? runFalsePositiveSuite(oracles, canaryOpt) : Promise.resolve(undefined),
    // The adaptive loop calls a live model, so it cannot be replayed identically
    // on both sides of a comparison: it attacks the system as configured
    // (defended, when defenses are on) and lands in that column only.
    args.adaptive ? adaptiveRun(args, resolved, attackedTarget, oracles) : Promise.resolve([]),
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
      ...(comparison !== undefined ? { defense: comparison } : {}),
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
    if (report.defense) renderDefenseComparison(report.defense, human);
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
    { defended: comparison !== undefined },
  );
  human.out(`\n${verdict.line}`);
  return verdict.exitCode;
}

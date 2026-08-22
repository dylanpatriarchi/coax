/**
 * The COAX flag table, parser, and generated help.
 *
 * WHY: the milestone-1 CLI reached into `argv.indexOf('--seed')` once per flag
 * and hand-wrote its usage text, so every new flag meant three edits in three
 * places and the help drifted from reality the first time someone forgot one.
 * Everything the CLI accepts is therefore declared exactly ONCE, in `FLAGS`
 * below: the parser, the zod validation, and `renderHelp()` all read that same
 * table, so a flag cannot exist without being documented and validated — and a
 * later PR can add `--defense` / `--trials` by appending one entry.
 *
 * Design decisions:
 *   - No CLI framework. COAX ships one runtime dependency (zod) and that stays
 *     true; this parser is small and does exactly what the tool needs:
 *     `--flag value`, `--flag=value`, `--no-flag` negation, repeatable/comma
 *     list flags, and errors that name the offending flag.
 *   - Validation is zod rather than hand-rolled `Number.isFinite` checks, so
 *     `--max-asr 3` fails as loudly and as legibly as a malformed config file.
 *   - Parsing never touches the network, the filesystem, or `process.exit`: it
 *     returns typed options or throws `CliError`, so it is unit-testable.
 */
import { z } from 'zod';
import { AttackSurfaceSchema, SeveritySchema } from '../core/attack.js';
import { EXIT_CODES_HELP } from './exit-codes.js';

export const COMMANDS = ['scan', 'list', 'demo', 'version', 'help'] as const;
export type CommandName = (typeof COMMANDS)[number];

/** A usage error: never a stack trace, always an actionable message. */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode: number = 1,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

type FlagKind = 'boolean' | 'string' | 'number' | 'list';

interface FlagSpec {
  /** The long flag as typed, without the leading `--`. */
  readonly flag: string;
  readonly kind: FlagKind;
  readonly commands: readonly CommandName[];
  readonly describe: string;
  /** Value placeholder shown in help, e.g. `DIR`. */
  readonly placeholder?: string;
  /** Validates the pre-coerced value; carries the default, if any. */
  readonly schema: z.ZodTypeAny;
}

const ratio = (): z.ZodNumber => z.number().min(0).max(1);

/**
 * The single source of truth. Keys are the option names commands consume;
 * `flag` is what the user types.
 */
const FLAGS = {
  // --- scan: target & determinism -------------------------------------------
  target: {
    flag: 'target',
    kind: 'string',
    commands: ['scan'],
    placeholder: 'PATH',
    describe: 'target module to load (default: the built-in vulnerable mock)',
    schema: z.string().min(1).optional(),
  },
  seed: {
    flag: 'seed',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'RNG seed — identical seeds produce identical payloads',
    schema: z.number().int().default(42),
  },
  iAmAuthorized: {
    flag: 'i-am-authorized',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'confirm you are authorized to test a non-localhost target',
    schema: z.boolean().default(false),
  },

  // --- scan: selection ------------------------------------------------------
  only: {
    flag: 'only',
    kind: 'list',
    commands: ['scan'],
    placeholder: 'IDS',
    describe: 'run only these attack module ids or families (comma-separated)',
    schema: z.array(z.string().min(1)).optional(),
  },
  exclude: {
    flag: 'exclude',
    kind: 'list',
    commands: ['scan'],
    placeholder: 'IDS',
    describe: 'skip these attack module ids or families (comma-separated)',
    schema: z.array(z.string().min(1)).optional(),
  },
  surface: {
    flag: 'surface',
    kind: 'list',
    commands: ['scan'],
    placeholder: 'SURFACES',
    describe: 'keep only payloads on these delivery surfaces',
    schema: z.array(AttackSurfaceSchema).optional(),
  },
  maxPayloads: {
    flag: 'max-payloads',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'cap the payloads each attack module emits',
    schema: z.number().int().positive().optional(),
  },
  scenarios: {
    flag: 'scenarios',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'run the multi-step scenarios (--no-scenarios to skip)',
    schema: z.boolean().default(true),
  },
  utility: {
    flag: 'utility',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'measure benign/under-attack utility (--no-utility to skip)',
    schema: z.boolean().default(true),
  },
  fp: {
    flag: 'fp',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'run the oracle false-positive suite (--no-fp to skip)',
    schema: z.boolean().default(true),
  },

  // --- scan: controls & statistics -----------------------------------------
  defense: {
    flag: 'defense',
    kind: 'list',
    commands: ['scan'],
    placeholder: 'IDS',
    describe: 'run behind these defenses ("all" for the default stack); gates the DEFENDED numbers',
    schema: z.array(z.string().min(1)).optional(),
  },
  trials: {
    flag: 'trials',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'send each payload N times; the report carries 95% intervals',
    schema: z.number().int().min(1).max(100).default(1),
  },

  // --- scan: adaptive attacker ---------------------------------------------
  adaptive: {
    flag: 'adaptive',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'run the closed-loop LLM attacker (requires --goal)',
    schema: z.boolean().default(false),
  },
  goal: {
    flag: 'goal',
    kind: 'string',
    commands: ['scan'],
    placeholder: 'TEXT',
    describe: 'attacker objective for --adaptive',
    schema: z.string().min(1).optional(),
  },
  maxIterations: {
    flag: 'max-iterations',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'adaptive loop iteration cap',
    schema: z.number().int().positive().max(100).default(6),
  },
  maxModelCalls: {
    flag: 'max-model-calls',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'adaptive attacker-model call cap (default: --max-iterations)',
    schema: z.number().int().positive().max(500).optional(),
  },
  persist: {
    flag: 'persist',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'adaptive: keep one session across iterations (true crescendo)',
    schema: z.boolean().default(false),
  },

  // --- scan: throughput -----------------------------------------------------
  concurrency: {
    flag: 'concurrency',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'attempts in flight (results stay ordered either way)',
    schema: z.number().int().min(1).max(64).default(1),
  },
  retries: {
    flag: 'retries',
    kind: 'number',
    commands: ['scan'],
    placeholder: 'N',
    describe: 'retries with exponential backoff on transient target failures',
    schema: z.number().int().min(0).max(10).default(0),
  },

  // --- scan: output ---------------------------------------------------------
  out: {
    flag: 'out',
    kind: 'string',
    commands: ['scan'],
    placeholder: 'DIR',
    describe: 'write report.md, report.html and report.json into DIR',
    schema: z.string().min(1).optional(),
  },
  json: {
    flag: 'json',
    kind: 'boolean',
    commands: ['scan', 'list'],
    describe: 'print machine-readable JSON on stdout (human output to stderr)',
    schema: z.boolean().default(false),
  },
  dryRun: {
    flag: 'dry-run',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'print the payload set that WOULD be sent; never contacts the target',
    schema: z.boolean().default(false),
  },

  // --- scan: policy & trend -------------------------------------------------
  failOnSeverity: {
    flag: 'fail-on-severity',
    kind: 'string',
    commands: ['scan'],
    placeholder: 'SEV',
    describe: 'exit 3 if any finding is at or above low|medium|high|critical',
    schema: SeveritySchema.optional(),
  },
  maxAsr: {
    flag: 'max-asr',
    kind: 'number',
    commands: ['scan'],
    placeholder: '0..1',
    describe: 'exit 3 if the overall ASR exceeds this ratio',
    schema: ratio().optional(),
  },
  maxWeightedAsr: {
    flag: 'max-weighted-asr',
    kind: 'number',
    commands: ['scan'],
    placeholder: '0..1',
    describe: 'exit 3 if the severity-weighted ASR exceeds this ratio',
    schema: ratio().optional(),
  },
  baseline: {
    flag: 'baseline',
    kind: 'string',
    commands: ['scan'],
    placeholder: 'FILE',
    describe: 'a previous report.json to diff this run against',
    schema: z.string().min(1).optional(),
  },
  failOnRegression: {
    flag: 'fail-on-regression',
    kind: 'boolean',
    commands: ['scan'],
    describe: 'exit 3 if any family got worse than --baseline',
    schema: z.boolean().default(false),
  },
} as const satisfies Record<string, FlagSpec>;

type FlagKey = keyof typeof FLAGS;

/** Option keys a given command accepts. */
type KeysFor<C extends CommandName> = {
  [K in FlagKey]: C extends (typeof FLAGS)[K]['commands'][number] ? K : never;
}[FlagKey];

/** The typed options a command receives, derived from the table itself. */
export type ArgsFor<C extends CommandName> = {
  [K in KeysFor<C>]: z.infer<(typeof FLAGS)[K]['schema']>;
};

export type ScanArgs = ArgsFor<'scan'>;
export type ListArgs = ArgsFor<'list'>;

export const LIST_KINDS = [
  'all',
  'attacks',
  'oracles',
  'adapters',
  'scenarios',
  'defenses',
] as const;
export type ListKind = (typeof LIST_KINDS)[number];

export type Parsed =
  | { command: 'scan'; args: ScanArgs }
  | { command: 'list'; args: ListArgs; kind: ListKind }
  | { command: 'demo' }
  | { command: 'version' }
  | { command: 'help'; topic?: CommandName };

function specsFor(command: CommandName): [FlagKey, FlagSpec][] {
  return (Object.entries(FLAGS) as [FlagKey, FlagSpec][]).filter(([, s]) =>
    s.commands.includes(command),
  );
}

function findSpec(command: CommandName, flag: string): [FlagKey, FlagSpec] | undefined {
  return specsFor(command).find(([, s]) => s.flag === flag);
}

/** A flag that exists, but not here — say so instead of "unknown flag". */
function definedElsewhere(flag: string): FlagSpec | undefined {
  return (Object.values(FLAGS) as FlagSpec[]).find((s) => s.flag === flag);
}

function unknownFlag(command: CommandName, flag: string): CliError {
  const elsewhere = definedElsewhere(flag);
  if (elsewhere) {
    return new CliError(
      `--${flag} is not a flag of "coax ${command}" (valid for: ${elsewhere.commands.join(', ')}).`,
    );
  }
  const available = specsFor(command).map(([, s]) => `--${s.flag}`);
  return new CliError(
    `unknown flag "--${flag}" for "coax ${command}". Available: ${available.join(', ') || '(none)'}`,
  );
}

function coerceNumber(flag: string, raw: string): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    throw new CliError(`--${flag} expects a number, got "${raw}".`);
  }
  return n;
}

function coerceBoolean(flag: string, raw: string): boolean {
  const v = raw.trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(v)) return true;
  if (['false', '0', 'no', 'off'].includes(v)) return false;
  throw new CliError(`--${flag} is a boolean flag; "${raw}" is not true/false.`);
}

function splitList(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

interface RawParse {
  values: Record<string, unknown>;
  positionals: string[];
  help: boolean;
}

/** Token walk: turns argv into a raw record, guided by the table. */
function parseTokens(command: CommandName, tokens: readonly string[]): RawParse {
  const values: Record<string, unknown> = {};
  const positionals: string[] = [];
  let help = false;

  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i] as string;

    if (token === '--help' || token === '-h') {
      help = true;
      continue;
    }
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }

    const body = token.slice(2);
    if (body.length === 0) throw new CliError('"--" is not a valid flag.');

    const eq = body.indexOf('=');
    const name = eq >= 0 ? body.slice(0, eq) : body;
    const inline = eq >= 0 ? body.slice(eq + 1) : undefined;

    // `--no-x` negation, for booleans only.
    if (name.startsWith('no-') && !findSpec(command, name)) {
      const positive = name.slice(3);
      const negated = findSpec(command, positive);
      if (!negated) throw unknownFlag(command, name);
      const [key, spec] = negated;
      if (spec.kind !== 'boolean') {
        throw new CliError(
          `--${name} is not valid: --${positive} takes a value, so it cannot be negated.`,
        );
      }
      if (inline !== undefined) throw new CliError(`--${name} does not take a value.`);
      values[key] = false;
      continue;
    }

    const found = findSpec(command, name);
    if (!found) throw unknownFlag(command, name);
    const [key, spec] = found;

    if (spec.kind === 'boolean') {
      values[key] = inline === undefined ? true : coerceBoolean(name, inline);
      continue;
    }

    // Value flags: `--flag=value` or `--flag value`.
    let raw = inline;
    if (raw === undefined) {
      const next = tokens[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new CliError(
          `--${name} expects a value${spec.placeholder ? ` (<${spec.placeholder}>)` : ''}.`,
        );
      }
      raw = next;
      i += 1;
    }
    if (raw.length === 0) throw new CliError(`--${name} expects a non-empty value.`);

    if (spec.kind === 'number') {
      values[key] = coerceNumber(name, raw);
    } else if (spec.kind === 'list') {
      const items = splitList(raw);
      if (items.length === 0) throw new CliError(`--${name} expects a non-empty value.`);
      const prev = (values[key] as string[] | undefined) ?? [];
      values[key] = [...prev, ...items];
    } else {
      values[key] = raw;
    }
  }

  return { values, positionals, help };
}

/** Run the raw record through the table's zod schemas. */
function validate<C extends CommandName>(command: C, values: Record<string, unknown>): ArgsFor<C> {
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const [key, spec] of specsFor(command)) shape[key] = spec.schema;
  const result = z.object(shape).safeParse(values);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => {
        const key = String(issue.path[0] ?? '');
        const spec = (FLAGS as Record<string, FlagSpec>)[key];
        return `--${spec?.flag ?? key}: ${issue.message}`;
      })
      .join('; ');
    throw new CliError(`invalid flag value — ${detail}`);
  }
  return result.data as ArgsFor<C>;
}

function asCommand(token: string): CommandName | undefined {
  return (COMMANDS as readonly string[]).includes(token) ? (token as CommandName) : undefined;
}

/**
 * Parse a full argv tail (i.e. `process.argv.slice(2)`).
 * Throws `CliError` on anything malformed; never exits.
 */
export function parseArgs(argv: readonly string[]): Parsed {
  const [first, ...rest] = argv;

  if (first === undefined) return { command: 'help' };
  if (first === '--version' || first === '-v') return { command: 'version' };
  if (first === '--help' || first === '-h') {
    const topic = rest[0] !== undefined ? asCommand(rest[0]) : undefined;
    return { command: 'help', ...(topic !== undefined ? { topic } : {}) };
  }

  const command = asCommand(first);
  if (command === undefined) {
    throw new CliError(`unknown command "${first}". Commands: ${COMMANDS.join(', ')}`);
  }
  if (command === 'help') {
    const topic = rest[0] !== undefined ? asCommand(rest[0]) : undefined;
    return { command: 'help', ...(topic !== undefined ? { topic } : {}) };
  }
  if (command === 'version') return { command: 'version' };

  const parsed = parseTokens(command, rest);
  if (parsed.help) return { command: 'help', topic: command };

  if (command === 'demo') {
    if (parsed.positionals.length > 0) {
      throw new CliError(`"coax demo" takes no arguments (got "${parsed.positionals[0]}").`);
    }
    return { command: 'demo' };
  }

  if (command === 'list') {
    if (parsed.positionals.length > 1) {
      throw new CliError(`"coax list" takes at most one kind (got ${parsed.positionals.length}).`);
    }
    const raw = parsed.positionals[0] ?? 'all';
    if (!(LIST_KINDS as readonly string[]).includes(raw)) {
      throw new CliError(`unknown kind "${raw}". Available: ${LIST_KINDS.join(', ')}`);
    }
    return { command: 'list', args: validate('list', parsed.values), kind: raw as ListKind };
  }

  if (parsed.positionals.length > 0) {
    throw new CliError(
      `unexpected argument "${parsed.positionals[0]}" — "coax scan" takes flags only.`,
    );
  }
  const args = validate('scan', parsed.values);
  if (args.adaptive && args.goal === undefined) {
    throw new CliError('--adaptive requires --goal "<attacker objective>".');
  }
  if (args.failOnRegression && args.baseline === undefined) {
    throw new CliError('--fail-on-regression requires --baseline <report.json>.');
  }
  return { command: 'scan', args };
}

const USAGE: { command: CommandName; syntax: string; describe: string }[] = [
  {
    command: 'scan',
    syntax: 'coax scan [flags]',
    describe: 'run the attack suite, score it, enforce thresholds',
  },
  {
    command: 'list',
    syntax: 'coax list [kind]',
    describe: `list registered modules — kind: ${LIST_KINDS.join(' | ')}`,
  },
  {
    command: 'demo',
    syntax: 'coax demo',
    describe: 'drive the vulnerable mock agent through a few probes',
  },
  { command: 'version', syntax: 'coax version', describe: 'print the version' },
  { command: 'help', syntax: 'coax help [command]', describe: 'show this help' },
];

function defaultNote(spec: FlagSpec): string {
  const def = spec.schema.safeParse(undefined);
  if (!def.success || def.data === undefined) return '';
  if (spec.kind === 'boolean') return def.data === true ? ' [default: on]' : '';
  return ` [default: ${String(def.data)}]`;
}

function flagLines(command: CommandName): string[] {
  const specs = specsFor(command);
  const left = specs.map(([, s]) => {
    const value = s.kind === 'boolean' ? '' : ` <${s.placeholder ?? 'VALUE'}>`;
    return `  --${s.flag}${value}`;
  });
  const width = Math.max(...left.map((l) => l.length), 0);
  return specs.map(
    ([, s], i) => `${(left[i] as string).padEnd(width + 2)}${s.describe}${defaultNote(s)}`,
  );
}

/** The help text — generated from `FLAGS`, so it cannot drift from the parser. */
export function renderHelp(topic?: CommandName): string {
  const out: string[] = [];
  out.push('COAX — automated red-teaming for LLM agents');
  out.push('');
  out.push('Usage:');
  const shown = topic ? USAGE.filter((u) => u.command === topic) : USAGE;
  const width = Math.max(...shown.map((u) => u.syntax.length));
  for (const u of shown) out.push(`  ${u.syntax.padEnd(width + 2)}${u.describe}`);

  for (const { command } of shown) {
    const lines = flagLines(command);
    if (lines.length === 0) continue;
    out.push('');
    out.push(`${command} flags:`);
    out.push(...lines);
  }

  out.push('');
  out.push('Exit codes:');
  out.push(...EXIT_CODES_HELP);
  out.push('');
  out.push('Without --target, scans the built-in vulnerable mock. A non-localhost --target');
  out.push('endpoint requires --i-am-authorized (or COAX_I_AM_AUTHORIZED=true).');
  out.push('');
  out.push('With --defense, the report describes the DEFENDED system: findings, ASR and every');
  out.push('threshold above are the defended numbers, and the undefended baseline is reported');
  out.push('beside them as context. Gate on what you ship.');
  out.push('Only test systems you own or are authorized to test.');
  return out.join('\n');
}

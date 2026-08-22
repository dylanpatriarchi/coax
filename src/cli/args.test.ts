import { describe, expect, it } from 'vitest';
import { CliError, parseArgs, renderHelp } from './args.js';

/** Narrow a parse to a scan, so the tests read as flat assertions. */
function scan(argv: string[]) {
  const parsed = parseArgs(argv);
  if (parsed.command !== 'scan') throw new Error(`expected a scan, got ${parsed.command}`);
  return parsed.args;
}

describe('parseArgs — commands', () => {
  it('defaults to help with no arguments', () => {
    expect(parseArgs([])).toMatchObject({ command: 'help' });
  });

  it('accepts version as a command and as a flag', () => {
    expect(parseArgs(['version']).command).toBe('version');
    expect(parseArgs(['--version']).command).toBe('version');
    expect(parseArgs(['-v']).command).toBe('version');
  });

  it('routes --help on a command to that command topic', () => {
    expect(parseArgs(['scan', '--help'])).toMatchObject({ command: 'help', topic: 'scan' });
    expect(parseArgs(['help', 'list'])).toMatchObject({ command: 'help', topic: 'list' });
  });

  it('rejects an unknown command with the list of real ones', () => {
    expect(() => parseArgs(['scam'])).toThrow(/unknown command "scam".*scan, list/s);
  });

  it('list takes an optional kind and rejects an unknown one', () => {
    expect(parseArgs(['list'])).toMatchObject({ command: 'list', kind: 'all' });
    expect(parseArgs(['list', 'oracles'])).toMatchObject({ command: 'list', kind: 'oracles' });
    expect(() => parseArgs(['list', 'wat'])).toThrow(/unknown kind "wat"/);
  });
});

describe('parseArgs — flag syntax', () => {
  it('accepts both --flag value and --flag=value', () => {
    expect(scan(['scan', '--seed', '7']).seed).toBe(7);
    expect(scan(['scan', '--seed=7']).seed).toBe(7);
    expect(scan(['scan', '--out=/tmp/x']).out).toBe('/tmp/x');
  });

  it('applies defaults from the flag table', () => {
    const args = scan(['scan']);
    expect(args.seed).toBe(42);
    expect(args.concurrency).toBe(1);
    expect(args.retries).toBe(0);
    expect(args.scenarios).toBe(true);
    expect(args.utility).toBe(true);
    expect(args.fp).toBe(true);
    expect(args.json).toBe(false);
    expect(args.target).toBeUndefined();
  });

  it('supports --no-x negation for booleans only', () => {
    const args = scan(['scan', '--no-scenarios', '--no-utility', '--no-fp']);
    expect(args.scenarios).toBe(false);
    expect(args.utility).toBe(false);
    expect(args.fp).toBe(false);
    expect(() => parseArgs(['scan', '--no-seed'])).toThrow(/cannot be negated/);
  });

  it('accepts an explicit boolean value', () => {
    expect(scan(['scan', '--json=true']).json).toBe(true);
    expect(scan(['scan', '--json=false']).json).toBe(false);
    expect(() => parseArgs(['scan', '--json=maybe'])).toThrow(/not true\/false/);
  });

  it('splits list flags on commas and accumulates repeats', () => {
    expect(scan(['scan', '--only', 'jailbreak,tool-abuse']).only).toEqual([
      'jailbreak',
      'tool-abuse',
    ]);
    expect(scan(['scan', '--only', 'a', '--only', 'b']).only).toEqual(['a', 'b']);
  });

  it('parses negative and fractional values', () => {
    expect(scan(['scan', '--seed', '-3']).seed).toBe(-3);
    expect(scan(['scan', '--max-asr', '0.25']).maxAsr).toBe(0.25);
  });
});

describe('parseArgs — errors', () => {
  it('names the offending flag when a value is missing', () => {
    expect(() => parseArgs(['scan', '--out'])).toThrow(/--out expects a value \(<DIR>\)/);
    expect(() => parseArgs(['scan', '--seed', '--json'])).toThrow(/--seed expects a value/);
  });

  it('rejects a non-numeric number', () => {
    expect(() => parseArgs(['scan', '--seed', 'abc'])).toThrow(
      /--seed expects a number, got "abc"/,
    );
  });

  it('rejects out-of-range and malformed values through zod', () => {
    expect(() => parseArgs(['scan', '--max-asr', '3'])).toThrow(/--max-asr/);
    expect(() => parseArgs(['scan', '--concurrency', '0'])).toThrow(/--concurrency/);
    expect(() => parseArgs(['scan', '--retries', '2.5'])).toThrow(/--retries/);
    expect(() => parseArgs(['scan', '--fail-on-severity', 'urgent'])).toThrow(/--fail-on-severity/);
    expect(() => parseArgs(['scan', '--surface', 'telepathy'])).toThrow(/--surface/);
  });

  it('validates the defense and trials flags', () => {
    expect(scan(['scan', '--defense', 'all']).defense).toEqual(['all']);
    expect(scan(['scan', '--defense', 'tool-guard,spotlighting']).defense).toEqual([
      'tool-guard',
      'spotlighting',
    ]);
    expect(scan(['scan']).trials).toBe(1);
    expect(scan(['scan', '--trials', '5']).trials).toBe(5);
    expect(() => parseArgs(['scan', '--trials', '0'])).toThrow(/--trials/);
    expect(() => parseArgs(['scan', '--trials', '2.5'])).toThrow(/--trials/);
    expect(() => parseArgs(['scan', '--defense'])).toThrow(/--defense expects a value/);
  });

  it('rejects an unknown flag and lists what is available', () => {
    expect(() => parseArgs(['scan', '--nope'])).toThrow(/unknown flag "--nope".*--target/s);
  });

  it('explains a flag that belongs to another command', () => {
    expect(() => parseArgs(['list', '--seed', '1'])).toThrow(
      /--seed is not a flag of "coax list" \(valid for: scan\)/,
    );
  });

  it('rejects stray positionals on scan and demo', () => {
    expect(() => parseArgs(['scan', 'everything'])).toThrow(/unexpected argument "everything"/);
    expect(() => parseArgs(['demo', 'now'])).toThrow(/takes no arguments/);
  });

  it('enforces cross-flag requirements', () => {
    expect(() => parseArgs(['scan', '--adaptive'])).toThrow(/--adaptive requires --goal/);
    expect(() => parseArgs(['scan', '--fail-on-regression'])).toThrow(
      /--fail-on-regression requires --baseline/,
    );
    expect(scan(['scan', '--adaptive', '--goal', 'leak the canary']).goal).toBe('leak the canary');
  });

  it('throws CliError with exit code 1, never a bare Error', () => {
    try {
      parseArgs(['scan', '--nope']);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).exitCode).toBe(1);
    }
  });
});

describe('parseArgs — global flags', () => {
  it('accepts --no-color and --quiet before or after the command', () => {
    expect(parseArgs(['--no-color', 'scan']).globals.color).toBe(false);
    expect(parseArgs(['scan', '--no-color']).globals.color).toBe(false);
    expect(parseArgs(['scan', '--color']).globals.color).toBe(true);
    expect(parseArgs(['--quiet', 'list']).globals.quiet).toBe(true);
    expect(parseArgs(['list', '--quiet']).globals.quiet).toBe(true);
  });

  it('leaves colour undecided when neither flag is given', () => {
    const parsed = parseArgs(['scan']);
    expect(parsed.globals.color).toBeUndefined();
    expect(parsed.globals.quiet).toBe(false);
  });

  it('works on a bare invocation and on demo, which take no other flags', () => {
    expect(parseArgs(['--quiet']).command).toBe('help');
    expect(parseArgs(['demo', '--no-color'])).toMatchObject({ command: 'demo' });
  });

  it('does not leak into the per-command flag namespace', () => {
    const scanArgs = scan(['scan', '--quiet']);
    expect('quiet' in scanArgs).toBe(false);
  });
});

describe('renderHelp', () => {
  it('is generated from the flag table, so every scan flag appears', () => {
    const help = renderHelp();
    for (const flag of [
      '--only',
      '--exclude',
      '--surface',
      '--max-payloads',
      '--adaptive',
      '--goal',
      '--concurrency',
      '--retries',
      '--dry-run',
      '--json',
      '--baseline',
      '--fail-on-severity',
      '--max-asr',
      '--max-weighted-asr',
      '--fail-on-regression',
      '--defense',
      '--trials',
    ]) {
      expect(help).toContain(flag);
    }
  });

  it('states which numbers the thresholds gate under --defense', () => {
    const help = renderHelp();
    expect(help).toContain('the report describes the DEFENDED system');
    expect(help).toContain('Gate on what you ship.');
  });

  it('documents the global flags', () => {
    const help = renderHelp();
    expect(help).toContain('global flags:');
    expect(help).toContain('--color');
    expect(help).toContain('--quiet');
  });

  it('documents the exit-code contract', () => {
    const help = renderHelp();
    expect(help).toContain('Exit codes:');
    expect(help).toContain('2  authorization refused');
    expect(help).toContain('3  policy threshold breached');
  });

  it('shows defaults and can be scoped to one command', () => {
    expect(renderHelp()).toContain('[default: 42]');
    const listHelp = renderHelp('list');
    expect(listHelp).toContain('coax list');
    expect(listHelp).not.toContain('--max-payloads');
    expect(listHelp).not.toContain('scan flags:');
  });
});

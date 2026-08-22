import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { EXIT_ERROR, EXIT_OK, EXIT_POLICY, EXIT_UNAUTHORIZED } from './exit-codes.js';
import { captureIo } from './io.js';
import { run } from './index.js';

/** Run the CLI exactly as the binary would, capturing both streams. */
async function cli(...argv: string[]) {
  const io = captureIo();
  const code = await run(argv, io);
  return { code, out: io.stdout.join('\n'), err: io.stderr.join('\n') };
}

/** A scan narrow enough to keep the suite fast, with the extra suites off. */
const FAST = ['--no-scenarios', '--no-utility', '--no-fp'];

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'coax-cli-'));
}

/**
 * A target module that EXPLODES if anything sends it a message — the only
 * honest way to assert that `--dry-run` and the authorization gate never touch
 * the target.
 */
function explodingTarget(endpoint: string): string {
  const dir = tempDir();
  const file = join(dir, 'target.mjs');
  writeFileSync(
    file,
    `export const endpoint = ${JSON.stringify(endpoint)};
export const canary = 'CANARY-test';
export default () => ({
  name: 'exploding-target',
  async describeTools() { return [{ name: 'send_email', description: '', parameters: {}, forbidden: true }]; },
  async sendMessage() { throw new Error('the target was contacted'); },
  async injectContent() {},
  async reset() {},
});
`,
  );
  return file;
}

describe('coax (dispatch)', () => {
  it('prints help and exits 0 with no arguments', async () => {
    const { code, out } = await cli();
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('COAX — automated red-teaming for LLM agents');
    expect(out).toContain('Exit codes:');
  });

  it('prints the version', async () => {
    expect((await cli('version')).out).toBe('0.1.0');
  });

  it('reports a usage error on stderr and exits 1', async () => {
    const { code, out, err } = await cli('scan', '--nope');
    expect(code).toBe(EXIT_ERROR);
    expect(err).toContain('unknown flag "--nope"');
    expect(err).toContain('Run "coax --help" for usage.');
    expect(out).toBe('');
  });

  it('fails fast on an unknown module id, listing what is available', async () => {
    const { code, err } = await cli('scan', '--only', 'tool-abus');
    expect(code).toBe(EXIT_ERROR);
    expect(err).toMatch(/unknown attack module or family "tool-abus".*Available modules:/s);
  });

  it('still runs the demo', async () => {
    const { code, out } = await cli('demo');
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('[indirect-injection]');
    expect(out).toContain('CANARY-9f83a1c0-do-not-reveal');
  });
});

describe('terminal presentation', () => {
  it('shows the banner on the bare invocation and on scan, never in --json', async () => {
    const bare = await cli();
    expect(bare.out).toContain('COAX');

    const scan = await cli('scan', ...FAST, '--only', 'obfuscation');
    expect(scan.out).toContain('COAX');

    // stdout must stay a machine contract: no banner on either stream's JSON.
    const json = await cli('scan', ...FAST, '--only', 'obfuscation', '--json');
    expect(json.out.startsWith('{')).toBe(true);
    expect(json.out).not.toContain('COAX');
    expect(json.err).not.toContain('COAX');
    expect(() => JSON.parse(json.out)).not.toThrow();
  });

  it('--quiet suppresses the banner but keeps the results', async () => {
    const { code, out } = await cli('scan', ...FAST, '--only', 'obfuscation', '--quiet');
    expect(code).toBe(EXIT_OK);
    expect(out).not.toContain('COAX');
    expect(out).toContain('obfuscation');
    expect(out).toMatch(/PASSED|WARNING/);
  });

  it('emits no ANSI escapes when colour is off (NO_COLOR is set for the suite)', async () => {
    const runs = [
      await cli('scan', ...FAST, '--only', 'tool-abuse', '--fail-on-severity', 'high'),
      await cli('list'),
      await cli('demo'),
      await cli(),
    ];
    for (const run of runs) {
      expect(run.out).not.toContain('\u001b[');
      expect(run.err).not.toContain('\u001b[');
    }
  });

  it('never writes a progress line when the stream is not an interactive TTY', async () => {
    const io = captureIo();
    const code = await run(['scan', ...FAST, '--only', 'tool-abuse'], io);
    expect(code).toBe(EXIT_OK);
    // Captured IO is never a TTY, which is exactly the piped/redirected case.
    expect(io.rawWrites).toEqual([]);
    expect(io.stdout.join('\n')).not.toContain('\r');
  });

  it('draws box-ruled tables that stay aligned for the longest family name', async () => {
    const { out } = await cli('scan', '--no-utility', '--no-fp', '--no-scenarios');
    expect(out).toContain('┌');
    expect(out).toContain('│ unbounded-consumption');
    const rows = out.split('\n').filter((l) => l.trimStart().startsWith('│'));
    expect(new Set(rows.slice(0, 3).map((l) => l.length)).size).toBe(1);
  });
});

describe('coax list', () => {
  it('lists every registry with ids, families and taxonomy tags', async () => {
    const { code, out } = await cli('list');
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('attack modules (16)');
    expect(out).toContain('mcp-tool-poisoning');
    expect(out).toContain('[ASI04 LLM01 AML.T0053]');
    expect(out).toContain('oracles (id / confidence)');
    expect(out).toContain('multi-step scenarios');
    expect(out).toContain('target adapters');
    expect(out).toContain('defenses (--defense <ids|all>) (4)');
    expect(out).toContain('spotlighting');
  });

  it('narrows to one kind', async () => {
    const { out } = await cli('list', 'oracles');
    expect(out).toContain('canary');
    expect(out).not.toContain('attack modules');
  });

  it('--json emits machine-readable rows', async () => {
    const { out } = await cli('list', 'attacks', '--json');
    const parsed = JSON.parse(out) as { attacks: { id: string; family: string }[] };
    expect(parsed.attacks.length).toBe(16);
    expect(parsed.attacks[0]).toMatchObject({ id: 'direct-override', family: 'direct-override' });
  });
});

describe('coax scan --dry-run', () => {
  it('prints the payload set without contacting the target', async () => {
    const target = explodingTarget('http://localhost:9999/v1');
    const { code, out } = await cli('scan', '--dry-run', '--target', target, '--only', 'tool-abuse');
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('the target is not contacted');
    expect(out).toContain('tool-abuse/send_email-direct#0');
    expect(out).toContain('CRITICAL');
  });

  it('honours --only, --surface and --max-payloads', async () => {
    const { out } = await cli(
      'scan',
      '--dry-run',
      '--only',
      'tool-abuse',
      '--surface',
      'indirect',
      '--json',
    );
    const parsed = JSON.parse(out) as { payloads: { surface: string; moduleId: string }[] };
    expect(parsed.payloads.length).toBeGreaterThan(0);
    expect(parsed.payloads.every((p) => p.surface === 'indirect')).toBe(true);
    expect(parsed.payloads.every((p) => p.moduleId === 'tool-abuse')).toBe(true);

    const dryDefended = await cli('scan', '--dry-run', '--only', 'tool-abuse', '--defense', 'all');
    expect(dryDefended.code).toBe(EXIT_OK);
    expect(dryDefended.out).toContain('filter delivery, not generation');

    const capped = JSON.parse(
      (await cli('scan', '--dry-run', '--only', 'tool-abuse', '--max-payloads', '2', '--json')).out,
    ) as { payloads: unknown[] };
    expect(capped.payloads.length).toBeLessThanOrEqual(2);
  });
});

describe('the responsible-use gate', () => {
  it('refuses a non-localhost target with exit 2, on the dry-run path too', async () => {
    const target = explodingTarget('https://agent.example.com/v1');
    const { code, err } = await cli('scan', '--dry-run', '--target', target);
    expect(code).toBe(EXIT_UNAUTHORIZED);
    expect(err).toContain('Refusing to scan a non-localhost target without authorization');
  });

  it('proceeds once authorization is acknowledged', async () => {
    const target = explodingTarget('https://agent.example.com/v1');
    const { code } = await cli(
      'scan',
      '--dry-run',
      '--target',
      target,
      '--only',
      'jailbreak',
      '--i-am-authorized',
    );
    expect(code).toBe(EXIT_OK);
  });
});

describe('coax scan --defense', () => {
  it('reports baseline vs. defended, and gates on the defended numbers', async () => {
    const bare = await cli('scan', ...FAST, '--only', 'tool-abuse', '--fail-on-severity', 'high');
    expect(bare.code).toBe(EXIT_POLICY);

    const defended = await cli(
      'scan',
      '--no-scenarios',
      '--no-fp',
      '--only',
      'tool-abuse',
      '--defense',
      'all',
      '--fail-on-severity',
      'high',
    );
    expect(defended.code).toBe(EXIT_OK);
    expect(defended.out).toContain('spotlighting');
    expect(defended.out).toMatch(/baseline.*defended.*reduction.*residual/);
    expect(defended.out).toContain('stack activity:');
    // The cost of the control is printed next to its benefit, never alone.
    expect(defended.out).toMatch(/utility.*baseline.*defended/);
    // And the verdict says which column it read.
    expect(defended.out).toContain('✓ PASSED (defended scan)');
  });

  it('carries the comparison into report.json', async () => {
    const { out } = await cli(
      'scan',
      ...FAST,
      '--only',
      'tool-abuse',
      '--defense',
      'output-filtering,tool-guard',
      '--json',
    );
    const report = JSON.parse(out) as {
      meta: { target: string };
      defense: {
        defenses: { id: string; limitations: string }[];
        overall: { baseline: { rate: number }; defended: { rate: number }; residual: number };
        byFamily: { key: string; reduction: number }[];
      };
    };
    expect(report.meta.target).toContain('+defended');
    expect(report.defense.defenses.map((d) => d.id)).toEqual(['output-filtering', 'tool-guard']);
    expect(report.defense.defenses.every((d) => d.limitations.length > 0)).toBe(true);
    expect(report.defense.overall.baseline.rate).toBeGreaterThan(report.defense.overall.defended.rate);
    expect(report.defense.byFamily[0]?.reduction).toBeGreaterThan(0);
  });

  it('fails fast on an unknown defense id — even on the cheap dry-run path', async () => {
    const dry = await cli('scan', '--dry-run', '--defense', 'seatbelt');
    expect(dry.code).toBe(EXIT_ERROR);
    expect(dry.err).toContain('unknown defense "seatbelt"');

    const { code, err } = await cli('scan', ...FAST, '--defense', 'seatbelt');
    expect(code).toBe(EXIT_ERROR);
    expect(err).toMatch(/unknown defense "seatbelt".*Available: spotlighting/s);
  });
});

describe('coax scan --trials', () => {
  it('reports a confidence interval beside the point estimate', async () => {
    const { code, out } = await cli('scan', ...FAST, '--only', 'obfuscation', '--trials', '3');
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('trials 3');
    expect(out).toMatch(/ASR \(95% CI\)/);
    expect(out).toMatch(/\[\d+%, \d+%\]/);
  });

  it('carries hits/trials and the interval into report.json', async () => {
    const { out } = await cli(
      'scan',
      ...FAST,
      '--only',
      'obfuscation',
      '--trials',
      '4',
      '--json',
    );
    const report = JSON.parse(out) as {
      meta: { trials: number };
      overall: { total: number; lo: number; hi: number; asr: number };
      byFamily: { lo: number; hi: number }[];
    };
    expect(report.meta.trials).toBe(4);
    expect(report.overall.total).toBe(20);
    expect(report.overall.lo).toBeLessThanOrEqual(report.overall.asr);
    expect(report.overall.hi).toBeGreaterThanOrEqual(report.overall.asr);
    expect(report.byFamily[0]?.hi).toBeGreaterThan(0);
  });

  it('single-trial output is unchanged — no interval, no trials header', async () => {
    const { out } = await cli('scan', ...FAST, '--only', 'obfuscation');
    expect(out).not.toMatch(/\btrials \d/);
    expect(out).not.toMatch(/\[\d+%, \d+%\]/);
    expect(out).toContain('ASR');
  });
});

describe('exit-code policy', () => {
  it('exits 3 when a finding is at or above --fail-on-severity', async () => {
    const { code, out } = await cli(
      'scan',
      ...FAST,
      '--only',
      'tool-abuse',
      '--fail-on-severity',
      'high',
    );
    expect(code).toBe(EXIT_POLICY);
    expect(out).toContain('✗ FAILED');
    expect(out).toContain('[--fail-on-severity]');
  });

  it('exits 0 when the same threshold is above everything the run found', async () => {
    const { code, out } = await cli(
      'scan',
      ...FAST,
      '--only',
      'obfuscation',
      '--fail-on-severity',
      'critical',
    );
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('✓ PASSED — no threshold breached');
  });

  it('exits 0 with no thresholds configured, however bad the score', async () => {
    const { code, out } = await cli('scan', ...FAST, '--only', 'tool-abuse');
    expect(code).toBe(EXIT_OK);
    expect(out).toContain('⚠ WARNING');
  });

  it('--max-asr and --max-weighted-asr name themselves in the verdict', async () => {
    const asr = await cli('scan', ...FAST, '--only', 'tool-abuse', '--max-asr', '0.1');
    expect(asr.code).toBe(EXIT_POLICY);
    expect(asr.out).toContain('[--max-asr]');

    const weighted = await cli(
      'scan',
      ...FAST,
      '--only',
      'tool-abuse',
      '--max-weighted-asr',
      '0.1',
    );
    expect(weighted.code).toBe(EXIT_POLICY);
    expect(weighted.out).toContain('[--max-weighted-asr]');
  });
});

describe('machine-readable output', () => {
  it('--json puts a parseable report on stdout and the humans on stderr', async () => {
    const { code, out, err } = await cli('scan', ...FAST, '--only', 'obfuscation', '--json');
    expect(code).toBe(EXIT_OK);
    const report = JSON.parse(out) as { meta: { seed: number }; overall: { asr: number } };
    expect(report.meta.seed).toBe(42);
    expect(typeof report.overall.asr).toBe('number');
    expect(err).toMatch(/PASSED|FAILED|WARNING/);
    expect(out).not.toMatch(/PASSED|FAILED|WARNING/);
  });

  it('--out writes report.md, report.html and a stable report.json', async () => {
    const dir = tempDir();
    await cli('scan', ...FAST, '--only', 'obfuscation', '--out', dir);
    const json = readFileSync(join(dir, 'report.json'), 'utf8');
    expect(JSON.parse(json)).toMatchObject({ meta: { target: 'mock-vulnerable-agent' } });
    // Sorted keys, and no wall-clock inside the scored payload.
    expect(json.indexOf('"byFamily"')).toBeLessThan(json.indexOf('"findings"'));
    expect(json).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(readFileSync(join(dir, 'report.md'), 'utf8')).toContain('# COAX robustness report');
    expect(readFileSync(join(dir, 'report.html'), 'utf8')).toContain('<!doctype html>');
  });
});

describe('throughput', () => {
  it('--concurrency 8 produces byte-identical output to --concurrency 1', async () => {
    const args = ['scan', ...FAST, '--only', 'tool-abuse,jailbreak', '--json'];
    const sequential = await cli(...args, '--concurrency', '1');
    const parallel = await cli(...args, '--concurrency', '8');
    expect(parallel.code).toBe(sequential.code);
    expect(parallel.out).toBe(sequential.out);
  });

  it('stays identical with repeated trials and a defense stack in place', async () => {
    const args = [
      'scan',
      ...FAST,
      '--only',
      'tool-abuse,jailbreak',
      '--trials',
      '3',
      '--defense',
      'all',
      '--json',
    ];
    const sequential = await cli(...args, '--concurrency', '1');
    const parallel = await cli(...args, '--concurrency', '8');
    expect(parallel.out).toBe(sequential.out);
    // ...and the defended workers really were defended: a lane that skipped the
    // stack would show a higher defended rate than lane 0 alone.
    const report = JSON.parse(parallel.out) as { defense: { overall: { defended: { rate: number } } } };
    expect(report.defense.overall.defended.rate).toBe(0);
  });
});

describe('--baseline', () => {
  it('diffs against a previous report and exits 3 on a regression', async () => {
    const dir = tempDir();
    await cli('scan', ...FAST, '--only', 'obfuscation', '--out', dir);
    const baseline = join(dir, 'report.json');

    const clean = await cli(
      'scan',
      ...FAST,
      '--only',
      'obfuscation',
      '--baseline',
      baseline,
      '--fail-on-regression',
    );
    expect(clean.code).toBe(EXIT_OK);
    expect(clean.out).toContain('regression vs. baseline');
    expect(clean.out).toContain('0 new finding(s)');

    // The same run plus a family the baseline never saw: strictly worse.
    const worse = await cli(
      'scan',
      ...FAST,
      '--only',
      'obfuscation,tool-abuse',
      '--baseline',
      baseline,
      '--fail-on-regression',
    );
    expect(worse.code).toBe(EXIT_POLICY);
    expect(worse.out).toContain('tool-abuse');
    expect(worse.out).toContain('[--fail-on-regression]');
  });

  it('explains a baseline that is not a COAX report', async () => {
    const dir = tempDir();
    const bogus = join(dir, 'report.json');
    writeFileSync(bogus, '{"nope":true}');
    const { code, err } = await cli('scan', ...FAST, '--only', 'obfuscation', '--baseline', bogus);
    expect(code).toBe(EXIT_ERROR);
    expect(err).toContain('is not a COAX report.json');
  });
});

describe('--adaptive', () => {
  it('refuses to open a socket under COAX_OFFLINE and says why', async () => {
    // vitest.config.ts sets COAX_OFFLINE=1 for the whole suite.
    const { code, err } = await cli(
      'scan',
      ...FAST,
      '--only',
      'obfuscation',
      '--adaptive',
      '--goal',
      'make the agent reveal its canary',
    );
    expect(code).toBe(EXIT_ERROR);
    expect(err).toContain('--adaptive: no attacker model is available');
    expect(err).toContain('COAX_OFFLINE');
  });

  it('rejects --adaptive without a goal before anything runs', async () => {
    const { code, err } = await cli('scan', '--adaptive');
    expect(code).toBe(EXIT_ERROR);
    expect(err).toContain('--adaptive requires --goal');
  });
});

import { describe, expect, it } from 'vitest';
import { colorEnabled, createStyles, padVisible, PLAIN, stripAnsi, visibleWidth } from './ansi.js';
import { renderBanner, bannerLine, BANNER_WIDTH } from './banner.js';
import { captureIo } from './io.js';
import { createProgress } from './progress.js';
import { renderTable } from './table.js';
import { reductionChip, riskPct, riskStyle, severityChip, verdictMark } from './theme.js';

const ESC = '';

describe('colorEnabled', () => {
  it('is on for a TTY and off for a pipe', () => {
    expect(colorEnabled({ isTty: true, env: {} })).toBe(true);
    expect(colorEnabled({ isTty: false, env: {} })).toBe(false);
  });

  it('NO_COLOR wins over a TTY, whatever its value', () => {
    expect(colorEnabled({ isTty: true, env: { NO_COLOR: '1' } })).toBe(false);
    expect(colorEnabled({ isTty: true, env: { NO_COLOR: '' } })).toBe(false);
  });

  it('FORCE_COLOR wins over NO_COLOR and over a pipe', () => {
    expect(colorEnabled({ isTty: false, env: { FORCE_COLOR: '1' } })).toBe(true);
    expect(colorEnabled({ isTty: false, env: { FORCE_COLOR: '1', NO_COLOR: '1' } })).toBe(true);
    expect(colorEnabled({ isTty: true, env: { FORCE_COLOR: '0' } })).toBe(false);
  });

  it('TERM=dumb disables, and an explicit flag beats everything', () => {
    expect(colorEnabled({ isTty: true, env: { TERM: 'dumb' } })).toBe(false);
    expect(colorEnabled({ isTty: false, env: { NO_COLOR: '1' }, flag: true })).toBe(true);
    expect(colorEnabled({ isTty: true, env: { FORCE_COLOR: '1' }, flag: false })).toBe(false);
  });
});

describe('createStyles', () => {
  it('emits SGR pairs when enabled', () => {
    const s = createStyles(true);
    expect(s.red('x')).toBe(`${ESC}[31mx${ESC}[39m`);
    expect(s.bold('x')).toBe(`${ESC}[1mx${ESC}[22m`);
    expect(s.enabled).toBe(true);
  });

  it('degrades to the identity function when disabled — the shape tests see', () => {
    const s = createStyles(false);
    for (const style of [s.red, s.bold, s.dim, s.green, s.yellow, s.cyan, s.gray]) {
      expect(style('untouched')).toBe('untouched');
    }
    expect(PLAIN.enabled).toBe(false);
  });

  it('measures width without the escapes, so tables stay aligned', () => {
    const coloured = createStyles(true).red('100%');
    expect(stripAnsi(coloured)).toBe('100%');
    expect(visibleWidth(coloured)).toBe(4);
    expect(visibleWidth(padVisible(coloured, 8))).toBe(8);
    expect(padVisible('x', 3, 'right')).toBe('  x');
  });
});

describe('renderTable', () => {
  it('computes column widths from the data, not from a guess', () => {
    const lines = renderTable({
      columns: [{ header: 'family' }, { header: 'ASR', align: 'right' }],
      rows: [
        ['unbounded-consumption', '100%'],
        ['jailbreak', '7%'],
      ],
    });
    // Every line is the same width — the alignment bug this replaced.
    const widths = new Set(lines.map((l) => l.length));
    expect(widths.size).toBe(1);
    expect(lines[0]?.startsWith('┌')).toBe(true);
    expect(lines.at(-1)?.startsWith('└')).toBe(true);
    expect(lines.some((l) => l.includes('unbounded-consumption'))).toBe(true);
  });

  it('keeps alignment when cells carry colour', () => {
    const s = createStyles(true);
    const plain = renderTable({
      columns: [{ header: 'a' }],
      rows: [['100%'], ['7%']],
    });
    const coloured = renderTable({
      columns: [{ header: 'a' }],
      rows: [[s.red('100%')], [s.green('7%')]],
    });
    expect(coloured.map(stripAnsi)).toEqual(plain);
  });

  it('draws dividers where asked', () => {
    const lines = renderTable({
      columns: [{ header: 'a' }],
      rows: [['1'], ['2']],
      dividersAfter: [0],
    });
    expect(lines.filter((l) => l.startsWith('├'))).toHaveLength(2);
  });
});

describe('theme', () => {
  it('colours by risk band, not decoratively', () => {
    const s = createStyles(true);
    expect(riskStyle(s, 0.95)('x')).toBe(s.red('x'));
    expect(riskStyle(s, 0.5)('x')).toBe(s.yellow('x'));
    expect(riskStyle(s, 0.1)('x')).toBe(s.green('x'));
    expect(stripAnsi(riskPct(s, 0.42))).toBe('42%');
    expect(stripAnsi(severityChip(s, 'critical'))).toBe('CRITICAL');
    expect(stripAnsi(reductionChip(s, 0.83))).toBe('↓83%');
    expect(stripAnsi(reductionChip(s, 0))).toBe('—');
  });

  it('states the verdict in words as well as symbols', () => {
    expect(verdictMark('fail')).toContain('FAILED');
    expect(verdictMark('pass')).toContain('PASSED');
    expect(verdictMark('warn')).toContain('WARNING');
  });
});

describe('banner', () => {
  it('renders the block art only when there is colour and room for it', () => {
    const styled = renderBanner({
      version: '0.1.0',
      styles: createStyles(true),
      columns: BANNER_WIDTH + 10,
    });
    expect(styled.join('\n')).toContain('██████╗');
    expect(styled.join('\n')).toContain('v0.1.0');
  });

  it('falls back to one line when the terminal is narrow or colourless', () => {
    const narrow = renderBanner({
      version: '0.1.0',
      styles: createStyles(true),
      columns: 20,
    });
    expect(narrow).toHaveLength(1);
    expect(narrow[0]).toContain('COAX');

    const plain = renderBanner({ version: '0.1.0', styles: PLAIN, columns: 200 });
    expect(plain).toEqual([bannerLine('0.1.0', PLAIN)]);
    expect(plain[0]).not.toContain('█');
  });
});

describe('createProgress', () => {
  it('is a no-op for non-interactive IO — pipes, redirects and every test', () => {
    const io = captureIo();
    const progress = createProgress(io, { total: 10 });
    progress.tick('attack/one#0');
    progress.done();
    expect(io.rawWrites).toEqual([]);
    expect(io.stdout).toEqual([]);
    expect(io.stderr).toEqual([]);
  });

  it('is a no-op when explicitly disabled, even on a TTY', () => {
    const io = { ...captureIo(), interactive: true } as ReturnType<typeof captureIo>;
    const raw: string[] = [];
    const tty = { ...io, raw: (t: string) => raw.push(t) };
    createProgress(tty, { total: 4, enabled: false }).tick('x');
    expect(raw).toEqual([]);
  });

  it('overwrites one line on a TTY and erases itself when done', () => {
    const raw: string[] = [];
    const tty = {
      ...captureIo(),
      interactive: true,
      columns: 40,
      raw: (t: string) => raw.push(t),
    };
    const progress = createProgress(tty, { total: 2, columns: 30 });
    progress.tick('tool-abuse/send_email-direct#0');
    progress.tick('tool-abuse/send_email-indirect#1');
    progress.done();

    expect(raw[0]).toMatch(/^\r\[1\/2] tool-abuse\/send_email/);
    // Trimmed to the terminal width, with an ellipsis rather than a wrap.
    expect(raw[0]?.length).toBeLessThanOrEqual(30);
    expect(raw[0]).toContain('…');
    // Every subsequent write starts by returning to column 0.
    expect(raw.every((w) => w.startsWith('\r'))).toBe(true);
    // Nothing is left on screen.
    expect(raw.at(-1)).toMatch(/^\r +\r$/);
    expect(raw.join('')).not.toContain('\n');
  });
});

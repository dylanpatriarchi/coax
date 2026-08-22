/**
 * The CLI's output seam.
 *
 * WHY: commands that call `console.log` directly can only be tested by spying on
 * the console, and they cannot honour `--json` (where stdout must stay pure
 * machine-readable and every human line belongs on stderr). Every command takes
 * an `Io` instead, so the entry point wires the real console, tests capture the
 * lines, and JSON mode is a one-line re-route rather than a flag checked in
 * forty print statements.
 *
 * The seam also carries the TERMINAL CAPABILITIES — the style set and whether
 * the stream is interactive — for the same reason: a renderer that reached for
 * `process.stdout.isTTY` itself would be untestable and would light up escape
 * codes inside a captured test string. Captured IO is never a TTY and its styles
 * are the identity function, so tests assert on plain text, always.
 */
import { colorEnabled, createStyles, PLAIN } from './ansi.js';
import type { Styles } from './ansi.js';

export interface Io {
  /** Machine-readable / primary output: stdout. */
  out(line: string): void;
  /** Human commentary, warnings, verdicts in `--json` mode: stderr. */
  err(line: string): void;
  /** Styles for this stream. Identity functions when colour is off. */
  readonly style: Styles;
  /** True only for an interactive terminal: gates the progress line. */
  readonly interactive: boolean;
  /** Terminal width, when known. */
  readonly columns?: number | undefined;
  /** Unbuffered write to stderr with no newline — the progress line only. */
  raw?(text: string): void;
}

export interface ConsoleIoOptions {
  color?: boolean | undefined;
  env?: Record<string, string | undefined>;
}

/**
 * The real console. Colour is decided from the STDERR stream, because that is
 * where every human line goes in `--json` mode and a half-coloured session is
 * worse than a plain one.
 */
export function createConsoleIo(opts: ConsoleIoOptions = {}): Io {
  const env = opts.env ?? process.env;
  const interactive = process.stderr.isTTY === true;
  const enabled = colorEnabled({
    isTty: interactive,
    env,
    ...(opts.color !== undefined ? { flag: opts.color } : {}),
  });
  return {
    out: (line) => {
      console.log(line);
    },
    err: (line) => {
      console.error(line);
    },
    style: createStyles(enabled),
    interactive,
    columns: process.stderr.columns,
    raw: (text) => {
      process.stderr.write(text);
    },
  };
}

export const consoleIo: Io = createConsoleIo();

export interface CapturedIo extends Io {
  stdout: string[];
  stderr: string[];
  /** Everything written through `raw` — the progress line, if it ever ran. */
  rawWrites: string[];
}

/** Test double: keeps every line so assertions read like the terminal does. */
export function captureIo(): CapturedIo {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const rawWrites: string[] = [];
  return {
    stdout,
    stderr,
    rawWrites,
    out: (line) => stdout.push(line),
    err: (line) => stderr.push(line),
    style: PLAIN,
    interactive: false,
    columns: undefined,
    raw: (text) => rawWrites.push(text),
  };
}

/** Route human output to stderr when stdout is reserved for JSON. */
export function humanIo(io: Io, jsonMode: boolean): Io {
  if (!jsonMode) return io;
  return { ...io, out: io.err.bind(io), err: io.err.bind(io) };
}

/** Swallow human output entirely — `--quiet` for the banner and progress. */
export function silence(io: Io): Io {
  return { ...io, out: () => {}, err: () => {}, interactive: false };
}

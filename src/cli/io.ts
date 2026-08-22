/**
 * The CLI's output seam.
 *
 * WHY: commands that call `console.log` directly can only be tested by spying on
 * the console, and they cannot honour `--json` (where stdout must stay pure
 * machine-readable and every human line belongs on stderr). Every command takes
 * an `Io` instead, so the entry point wires the real console, tests capture the
 * lines, and the JSON mode is a one-line re-route rather than a flag checked in
 * forty print statements.
 */

export interface Io {
  /** Machine-readable / primary output: stdout. */
  out(line: string): void;
  /** Human commentary, warnings, verdicts in `--json` mode: stderr. */
  err(line: string): void;
}

export const consoleIo: Io = {
  out: (line) => {
    console.log(line);
  },
  err: (line) => {
    console.error(line);
  },
};

export interface CapturedIo extends Io {
  stdout: string[];
  stderr: string[];
}

/** Test double: keeps every line so assertions read like the terminal does. */
export function captureIo(): CapturedIo {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    stdout,
    stderr,
    out: (line) => stdout.push(line),
    err: (line) => stderr.push(line),
  };
}

/** Route human output to stderr when stdout is reserved for JSON. */
export function humanIo(io: Io, jsonMode: boolean): Io {
  return jsonMode ? { out: io.err.bind(io), err: io.err.bind(io) } : io;
}

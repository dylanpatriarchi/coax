/**
 * The in-flight progress line.
 *
 * WHY: a full suite against a real endpoint is minutes of silence, and silence
 * is indistinguishable from a hang — the operator's only recourse today is
 * Ctrl-C, which throws away the run. One overwritten line fixes that.
 *
 * Design decisions, all of them about what it must NOT do:
 *   - It writes with `\r` to STDERR and erases itself when finished, so it never
 *     touches stdout, never survives into a pipe, and cannot end up inside
 *     `--json` output or a redirected log.
 *   - It exists only when the stream is an interactive TTY. Piped, redirected,
 *     `--json`, or `--quiet` — it is never constructed at all, so there is no
 *     branch anywhere else in the CLI.
 *   - It carries NO information the report needs. Progress is a courtesy; the
 *     report bytes are identical whether or not anyone watched it happen.
 */
import type { Io } from './io.js';

export interface Progress {
  /** Record one completed unit of work. */
  tick(label: string): void;
  /** Erase the line. Safe to call twice, and always called on the error path. */
  done(): void;
}

/** A progress object that does nothing — the piped/quiet/json case. */
const NOOP: Progress = {
  tick: () => {},
  done: () => {},
};

export interface ProgressOptions {
  total: number;
  /** Columns available for the line; longer labels are trimmed to fit. */
  columns?: number | undefined;
  /** Caller veto — `--json` and `--quiet` both switch it off. */
  enabled?: boolean;
}

/**
 * Build a progress line, or the no-op when `io` is not an interactive terminal
 * (which includes every test, since captured IO is never a TTY).
 */
export function createProgress(io: Io, opts: ProgressOptions): Progress {
  if (opts.enabled === false || !io.interactive || io.raw === undefined || opts.total <= 0) {
    return NOOP;
  }
  const raw = io.raw.bind(io);
  const width = Math.max(20, (opts.columns ?? 80) - 1);
  let completed = 0;
  let painted = 0;

  const erase = (): void => {
    if (painted > 0) raw(`\r${' '.repeat(painted)}\r`);
    painted = 0;
  };

  return {
    tick(label: string): void {
      completed += 1;
      const counter = `[${completed}/${opts.total}]`;
      const room = width - counter.length - 1;
      const text = label.length > room ? `${label.slice(0, Math.max(0, room - 1))}…` : label;
      const line = `${counter} ${text}`;
      erase();
      raw(`\r${line}`);
      painted = line.length;
    },
    done: erase,
  };
}

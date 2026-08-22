/**
 * The COAX banner.
 *
 * WHY it is a module and not six `console.log`s: the banner is the one piece of
 * output that must be suppressed by three unrelated conditions — `--json` (where
 * stdout is a machine contract), `--quiet`, and a terminal too narrow or too
 * dumb to render the block art — and a rule enforced in three places is a rule
 * that will be broken in one of them. Everything that decides whether and how it
 * appears is here.
 *
 * The art degrades rather than disappears: on a narrow or non-TTY stream it
 * becomes a single line carrying the same three facts (name, purpose, version),
 * because a banner that mangles itself into a pipe is worse than no banner.
 */
import type { Io } from './io.js';
import type { Styles } from './ansi.js';

/** The one place the shipped version string lives. */
export const VERSION = '0.1.0';

const ART = [
  ' ██████╗ ██████╗  █████╗ ██╗  ██╗',
  '██╔════╝██╔═══██╗██╔══██╗╚██╗██╔╝',
  '██║     ██║   ██║███████║ ╚███╔╝',
  '██║     ██║   ██║██╔══██║ ██╔██╗',
  '╚██████╗╚██████╔╝██║  ██║██╔╝ ██╗',
  ' ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝',
];

const TAGLINE = 'automated red-teaming for LLM agents';

/** Widest line of the block art — the minimum terminal width it needs. */
export const BANNER_WIDTH = Math.max(...ART.map((l) => l.length));

export interface BannerOptions {
  version: string;
  styles: Styles;
  /** Columns available. Undefined (not a terminal) means "use the one-liner". */
  columns?: number | undefined;
}

/** The one-line form: same facts, no art. */
export function bannerLine(version: string, styles: Styles): string {
  return [
    styles.cyan('▚'),
    styles.bold('COAX'),
    styles.dim('·'),
    TAGLINE,
    styles.dim('·'),
    styles.dim(`v${version}`),
  ].join(' ');
}

/**
 * Render the banner. Returns the block art when there is room for it and the
 * stream can show colour, else the single line.
 */
export function renderBanner(opts: BannerOptions): string[] {
  const { styles, version } = opts;
  const columns = opts.columns ?? 0;
  if (!styles.enabled || columns < BANNER_WIDTH) return [bannerLine(version, styles)];

  return [
    ...ART.map((line) => styles.cyan(line)),
    `   ${TAGLINE} ${styles.dim('·')} ${styles.dim(`v${version}`)}`,
    '',
  ];
}

/**
 * Print the banner on a human-facing stream. Suppressed by `--quiet`; callers
 * are responsible for not calling it at all in `--json` mode, where stdout is a
 * machine contract.
 */
export function showBanner(io: Io, opts: { quiet: boolean }): void {
  if (opts.quiet) return;
  for (const line of renderBanner({ version: VERSION, styles: io.style, columns: io.columns })) {
    io.out(line);
  }
}

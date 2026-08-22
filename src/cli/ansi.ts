/**
 * ANSI styling, hand-rolled.
 *
 * WHY not a dependency: COAX ships exactly one runtime dependency (zod) and a
 * security tool asking a user to trust a colour library — a category with a
 * memorable supply-chain history — would be a poor advertisement for a project
 * whose own attack suite includes a supply-chain family. The whole of what we
 * need is thirty lines of SGR codes.
 *
 * Design decisions:
 *   - Detection lives here, once, and the ANSWER is a `Styles` object whose
 *     functions are the IDENTITY when colour is off. Call sites never branch on
 *     "are we coloured?", so the plain-text output is exactly the coloured text
 *     minus the escapes — and the test suite (colour forced off) asserts on
 *     clean strings.
 *   - `NO_COLOR` (any value, per no-color.org) and a non-TTY stream both mean
 *     no colour; `FORCE_COLOR` overrides in the other direction, which is what
 *     CI logs and `script`-wrapped runs need.
 *   - `visibleWidth` exists because every aligned table in the CLI would
 *     otherwise pad by the length of the escape sequences.
 */

export type Style = (text: string) => string;

export interface Styles {
  readonly enabled: boolean;
  bold: Style;
  dim: Style;
  underline: Style;
  red: Style;
  yellow: Style;
  green: Style;
  cyan: Style;
  blue: Style;
  magenta: Style;
  gray: Style;
}

const CODES = {
  bold: [1, 22],
  dim: [2, 22],
  underline: [4, 24],
  red: [31, 39],
  yellow: [33, 39],
  green: [32, 39],
  cyan: [36, 39],
  blue: [34, 39],
  magenta: [35, 39],
  gray: [90, 39],
} as const satisfies Record<string, readonly [number, number]>;

type StyleName = keyof typeof CODES;

const identity: Style = (text) => text;

function wrap(name: StyleName): Style {
  const [on, off] = CODES[name];
  return (text) => `\u001b[${on}m${text}\u001b[${off}m`;
}

/** Build a style set. Every helper is the identity function when disabled. */
export function createStyles(enabled: boolean): Styles {
  const names = Object.keys(CODES) as StyleName[];
  const styles = { enabled } as { enabled: boolean } & Record<StyleName, Style>;
  for (const name of names) styles[name] = enabled ? wrap(name) : identity;
  return styles;
}

/** Colour is off in both directions here — the shape tests and pipes see. */
export const PLAIN: Styles = createStyles(false);

export type EnvRecord = Record<string, string | undefined>;

export interface ColorInput {
  /** The stream the styled text is going to. */
  isTty?: boolean;
  env?: EnvRecord;
  /** `--no-color` / `--color`. Undefined means "not specified". */
  flag?: boolean | undefined;
}

/**
 * Decide whether to emit escapes. Precedence, highest first:
 * explicit flag, FORCE_COLOR, NO_COLOR, TERM=dumb, is-a-TTY.
 */
export function colorEnabled(input: ColorInput = {}): boolean {
  const env = input.env ?? {};
  if (input.flag !== undefined) return input.flag;

  const force = env['FORCE_COLOR'];
  if (force !== undefined) {
    // Node's own convention: FORCE_COLOR=0 is an explicit "off", not "unset".
    return force !== '0' && force.toLowerCase() !== 'false';
  }
  // Presence is enough, whatever the value: that is the NO_COLOR contract.
  if (env['NO_COLOR'] !== undefined) return false;
  if (env['TERM'] === 'dumb') return false;
  return input.isTty === true;
}

const ANSI_PATTERN = /\u001b\[[0-9;]*m/g;

/** Text with every SGR escape removed. */
export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, '');
}

/** Printable width, ignoring escapes — what column alignment must measure. */
export function visibleWidth(text: string): number {
  return stripAnsi(text).length;
}

/** Pad to `width` counting only visible characters. */
export function padVisible(text: string, width: number, align: 'left' | 'right' = 'left'): string {
  const pad = ' '.repeat(Math.max(0, width - visibleWidth(text)));
  return align === 'right' ? `${pad}${text}` : `${text}${pad}`;
}

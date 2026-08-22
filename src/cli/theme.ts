/**
 * What the colours MEAN.
 *
 * WHY a separate module: colour in a security tool is data, not decoration. A
 * reader must be able to learn one mapping — red is bad, green is fine — and
 * have it hold in every table, so the thresholds live here once instead of
 * being re-invented per renderer. Nothing here emits escapes itself; it picks a
 * `Style` from the caller's `Styles`, which is the identity function when colour
 * is off. Meaning therefore never depends on colour being available: every
 * coloured cell still carries its number, and every verdict still carries its
 * word.
 */
import type { Style, Styles } from './ansi.js';
import type { Severity } from '../core/attack.js';

/** ASR bands: >=80% red, 40-79% yellow, <40% green. */
export function riskStyle(styles: Styles, rate: number): Style {
  if (rate >= 0.8) return styles.red;
  if (rate >= 0.4) return styles.yellow;
  return styles.green;
}

/** The inverse reading: a DEFENDED or false-positive rate is good when low. */
export function goodWhenLow(styles: Styles, rate: number): Style {
  return rate === 0 ? styles.green : riskStyle(styles, rate);
}

const SEVERITY_STYLE = (styles: Styles): Record<Severity, Style> => ({
  critical: styles.red,
  high: styles.red,
  medium: styles.yellow,
  low: styles.green,
});

/** `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, coloured to match the risk bands. */
export function severityChip(styles: Styles, severity: Severity): string {
  return SEVERITY_STYLE(styles)[severity](severity.toUpperCase());
}

/** A percentage in the risk colour for its band. */
export function riskPct(styles: Styles, rate: number, digits = 0): string {
  return riskStyle(styles, rate)(`${(rate * 100).toFixed(digits)}%`);
}

/** A reduction, shown as the direction it moved: `↓83%`. */
export function reductionChip(styles: Styles, reduction: number): string {
  if (reduction <= 0) return styles.dim('—');
  return styles.green(`↓${(reduction * 100).toFixed(0)}%`);
}

export type VerdictLevel = 'pass' | 'warn' | 'fail';

const VERDICT_MARK: Record<VerdictLevel, string> = {
  pass: '✓ PASSED',
  warn: '⚠ WARNING',
  fail: '✗ FAILED',
};

/** The headline word + symbol for a verdict. Plain text; caller colours it. */
export function verdictMark(level: VerdictLevel): string {
  return VERDICT_MARK[level];
}

export function verdictStyle(styles: Styles, level: VerdictLevel): Style {
  if (level === 'fail') return styles.red;
  if (level === 'warn') return styles.yellow;
  return styles.green;
}

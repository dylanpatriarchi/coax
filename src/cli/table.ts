/**
 * Box-drawn tables for the terminal.
 *
 * WHY: the old summary padded columns to hardcoded widths, so the first module
 * whose name did not fit — `unbounded-consumption`, by one character — pushed
 * its own ASR column out of alignment and quietly made the whole table look
 * broken. Widths are computed from the DATA here, once, for every table the CLI
 * prints.
 *
 * Design decisions:
 *   - Cells arrive already styled. Column widths are measured with
 *     `visibleWidth`, so a red 100% occupies the same column as a green 0% and
 *     colour never shifts the layout.
 *   - The border is drawn, not implied by spaces: a report someone pastes into
 *     a ticket keeps its shape even when the surrounding font is proportional.
 *   - No wrapping and no truncation. A red-team payload id is an identifier
 *     someone will copy into `--only`; silently cutting it in half would be a
 *     worse sin than a wide table.
 */
import { padVisible, visibleWidth } from './ansi.js';

export interface Column {
  header: string;
  align?: 'left' | 'right';
}

export interface TableOptions {
  columns: readonly Column[];
  /** Row cells, already styled. Short rows are padded with empty cells. */
  rows: readonly (readonly string[])[];
  /** Prefix for every line — the CLI indents its tables by two spaces. */
  indent?: string;
  /** Rows after which to draw a divider (0-based index of the row above it). */
  dividersAfter?: readonly number[];
  /** Style applied to the border glyphs (usually `dim`). */
  border?: (text: string) => string;
}

const B = {
  h: '─',
  v: '│',
  tl: '┌',
  tr: '┐',
  bl: '└',
  br: '┘',
  lt: '├',
  rt: '┤',
  tt: '┬',
  bt: '┴',
  x: '┼',
} as const;

/** Render a table as lines, ready to hand to `Io.out`. */
export function renderTable(opts: TableOptions): string[] {
  const { columns, rows } = opts;
  const indent = opts.indent ?? '';
  const border = opts.border ?? ((t: string): string => t);
  const dividers = new Set(opts.dividersAfter ?? []);

  const widths = columns.map((col, i) =>
    rows.reduce(
      (max, row) => Math.max(max, visibleWidth(row[i] ?? '')),
      visibleWidth(col.header),
    ),
  );

  const rule = (left: string, mid: string, right: string): string =>
    border(`${left}${widths.map((w) => B.h.repeat(w + 2)).join(mid)}${right}`);

  const line = (cells: readonly string[]): string => {
    const body = widths
      .map((w, i) => ` ${padVisible(cells[i] ?? '', w, columns[i]?.align ?? 'left')} `)
      .join(border(B.v));
    return `${border(B.v)}${body}${border(B.v)}`;
  };

  const out: string[] = [];
  out.push(rule(B.tl, B.tt, B.tr));
  out.push(line(columns.map((c) => c.header)));
  out.push(rule(B.lt, B.x, B.rt));
  rows.forEach((row, i) => {
    out.push(line(row));
    if (dividers.has(i)) out.push(rule(B.lt, B.x, B.rt));
  });
  out.push(rule(B.bl, B.bt, B.br));
  return out.map((l) => `${indent}${l}`);
}

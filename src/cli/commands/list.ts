/**
 * `coax list` — what is actually in this build.
 *
 * WHY: the registries have always been able to enumerate themselves, but
 * nothing surfaced that, so the only way to learn the id you need for
 * `--only` was to read `src/attacks/index.ts`. Selection flags are useless
 * without discovery, so the two ship together.
 *
 * Design decision: one flat, greppable row per module — id, family, taxonomy —
 * because the first thing anyone does with this output is pipe it through grep
 * or copy an id into `--only`. `--json` emits the same rows for tooling.
 */
import { ADAPTER_KINDS } from '../../adapters/index.js';
import { createAttackRegistry } from '../../attacks/index.js';
import { createDefenseRegistry } from '../../defenses/index.js';
import { createOracleRegistry } from '../../oracles/index.js';
import { BUILTIN_SCENARIOS } from '../../scenarios/index.js';
import { EXIT_OK } from '../exit-codes.js';
import { canonicalJson } from '../json.js';
import { padVisible } from '../ansi.js';
import type { Io } from '../io.js';
import type { ListArgs, ListKind } from '../args.js';

interface Row {
  id: string;
  family?: string;
  taxonomy?: string[];
  detail: string;
}

interface Section {
  kind: Exclude<ListKind, 'all'>;
  title: string;
  rows: Row[];
  /** Shown instead of a table when the section is empty. */
  emptyNote?: string;
}

function attackRows(): Row[] {
  return createAttackRegistry()
    .list()
    .map((m) => ({ id: m.id, family: m.family, taxonomy: [...m.taxonomy], detail: m.description }));
}

function oracleRows(): Row[] {
  return createOracleRegistry()
    .list()
    .map((o) => ({ id: o.id, family: o.confidence, detail: o.description }));
}

function scenarioRows(): Row[] {
  return BUILTIN_SCENARIOS.map((s) => ({
    id: s.id,
    family: s.family,
    taxonomy: [...s.taxonomy],
    detail: `${s.surface} · ${s.severity} · ${s.description}`,
  }));
}

function adapterRows(): Row[] {
  return ADAPTER_KINDS.map((kind) => ({
    id: kind,
    detail: `built-in adapter (construct it in your --target module via create${kind}…)`,
  }));
}

/**
 * Defenses carry their LIMITATIONS into the listing, not just a description:
 * COAX measures controls, it does not market them, and the first question about
 * a mitigation is what it fails to stop.
 */
function defenseRows(): Row[] {
  return createDefenseRegistry()
    .list()
    .map((d) => ({
      id: d.id,
      detail: `${d.description} — does NOT stop: ${d.limitations}`,
    }));
}

function sections(kind: ListKind): Section[] {
  const all: Section[] = [
    { kind: 'attacks', title: 'attack modules', rows: attackRows() },
    { kind: 'oracles', title: 'oracles (id / confidence)', rows: oracleRows() },
    { kind: 'scenarios', title: 'multi-step scenarios', rows: scenarioRows() },
    { kind: 'adapters', title: 'target adapters', rows: adapterRows() },
    {
      kind: 'defenses',
      title: 'defenses (--defense <ids|all>)',
      rows: defenseRows(),
      emptyNote: 'none registered in this build',
    },
  ];
  return kind === 'all' ? all : all.filter((s) => s.kind === kind);
}

/**
 * Rows are grouped under their family when they have one: the registries are
 * long enough now that a flat list buries the structure, and "which jailbreak
 * modules do I have?" is the question people actually arrive with. Taxonomy tags
 * are dimmed — they are reference data, not the thing being scanned for.
 */
function renderSection(io: Io, section: Section): void {
  const s = io.style;
  io.out(`${s.bold(section.title)} ${s.dim(`(${section.rows.length})`)}`);
  if (section.rows.length === 0) {
    io.out(`  ${s.dim(section.emptyNote ?? '(none)')}`);
    return;
  }

  const idWidth = Math.max(...section.rows.map((r) => r.id.length));
  const line = (row: Row, indent: string): string => {
    const tags =
      row.taxonomy && row.taxonomy.length > 0 ? `${s.dim(`[${row.taxonomy.join(' ')}]`)} ` : '';
    return `${indent}${s.cyan(padVisible(row.id, idWidth))}  ${tags}${s.dim(row.detail)}`;
  };

  const grouped = section.rows.every((r) => r.family !== undefined);
  if (!grouped) {
    for (const row of section.rows) io.out(line(row, '  '));
    return;
  }

  const families = new Map<string, Row[]>();
  for (const row of section.rows) {
    const key = row.family as string;
    families.set(key, [...(families.get(key) ?? []), row]);
  }
  for (const [family, rows] of families) {
    io.out(`  ${s.bold(family)}`);
    for (const row of rows) io.out(line(row, '    '));
  }
}

export function runListCommand(args: ListArgs, kind: ListKind, io: Io): number {
  const found = sections(kind);

  if (args.json) {
    const payload: Record<string, Row[]> = {};
    for (const s of found) payload[s.kind] = s.rows;
    io.out(canonicalJson(payload).trimEnd());
    return EXIT_OK;
  }

  found.forEach((section, index) => {
    if (index > 0) io.out('');
    renderSection(io, section);
  });
  return EXIT_OK;
}

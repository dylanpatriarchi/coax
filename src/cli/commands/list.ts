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
import { createOracleRegistry } from '../../oracles/index.js';
import { BUILTIN_SCENARIOS } from '../../scenarios/index.js';
import { EXIT_OK } from '../exit-codes.js';
import { canonicalJson } from '../json.js';
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
 * Defenses are registered by the defense layer. Until that ships, the section
 * exists and reports honestly rather than pretending the concept doesn't.
 */
function defenseRows(): Row[] {
  return [];
}

function sections(kind: ListKind): Section[] {
  const all: Section[] = [
    { kind: 'attacks', title: 'attack modules', rows: attackRows() },
    { kind: 'oracles', title: 'oracles (id / confidence)', rows: oracleRows() },
    { kind: 'scenarios', title: 'multi-step scenarios', rows: scenarioRows() },
    { kind: 'adapters', title: 'target adapters', rows: adapterRows() },
    {
      kind: 'defenses',
      title: 'defenses',
      rows: defenseRows(),
      emptyNote: 'none registered in this build',
    },
  ];
  return kind === 'all' ? all : all.filter((s) => s.kind === kind);
}

function renderSection(io: Io, section: Section): void {
  io.out(`${section.title} (${section.rows.length}):`);
  if (section.rows.length === 0) {
    io.out(`  ${section.emptyNote ?? '(none)'}`);
    return;
  }
  const idWidth = Math.max(...section.rows.map((r) => r.id.length));
  const famWidth = Math.max(...section.rows.map((r) => (r.family ?? '').length));
  for (const row of section.rows) {
    const family = famWidth > 0 ? `${(row.family ?? '').padEnd(famWidth + 2)}` : '';
    const tags = row.taxonomy && row.taxonomy.length > 0 ? `[${row.taxonomy.join(' ')}] ` : '';
    io.out(`  ${row.id.padEnd(idWidth + 2)}${family}${tags}${row.detail}`);
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

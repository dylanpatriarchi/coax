/**
 * Canonical JSON for the machine-readable report.
 *
 * WHY: `--json` and `report.json` only earn their keep if two runs can be
 * diffed. `JSON.stringify` preserves insertion order, which means a harmless
 * refactor that builds an object's fields in a different order shows up as a
 * whole-file diff and buries the one ASR that actually moved. Sorting keys
 * recursively makes the output a stable text artifact: byte-identical inputs
 * produce byte-identical files, and a real change is a small hunk.
 *
 * Arrays keep their order — the report deliberately sorts findings by severity
 * and category rows by key, and that order is meaning, not noise.
 */

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

function canonicalize(value: unknown): Json {
  if (value === null || typeof value !== 'object') {
    // `undefined` never survives JSON anyway; normalise it away up front so a
    // key that is absent and a key that is explicitly undefined can't differ.
    return (value === undefined ? null : value) as Json;
  }
  if (Array.isArray(value)) return value.map(canonicalize);

  const source = value as Record<string, unknown>;
  const out: { [key: string]: Json } = {};
  for (const key of Object.keys(source).sort()) {
    const v = source[key];
    if (v === undefined) continue;
    out[key] = canonicalize(v);
  }
  return out;
}

/** Deterministic, diffable JSON with sorted keys and a trailing newline. */
export function canonicalJson(value: unknown, indent = 2): string {
  return `${JSON.stringify(canonicalize(value), null, indent)}\n`;
}

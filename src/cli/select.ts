/**
 * Module selection for `coax scan --only / --exclude / --surface`.
 *
 * WHY: the registries have always been able to `list()` and `get()` by id, but
 * the CLI ran the whole suite unconditionally — so "re-run just the tool-abuse
 * finding" meant editing TypeScript. Selection lives here, not in the scan
 * command, because it is pure set logic and deserves its own tests.
 *
 * Design decisions:
 *   - A selector matches a module id OR an `AttackFamily`, because that is what
 *     people actually type (`--only tool-abuse` is a family;
 *     `--only mcp-tool-poisoning` is a module). Where a name is both — several
 *     modules share their family's name — it resolves to the whole FAMILY, the
 *     superset: someone who writes `--only jailbreak` means every jailbreak
 *     attack, and silently running one sixteenth of the suite would be the
 *     worse surprise.
 *   - An unrecognised selector is a hard error listing what IS available —
 *     the same contract `Registry.get()` already sets. A typo that silently
 *     scanned nothing would be the worst possible failure mode for a CI gate.
 *   - `--surface` filters PAYLOADS, not modules: a single module can emit both
 *     direct and indirect variants, so filtering it at module granularity would
 *     quietly drop the wrong half.
 */
import type { AttackFamily, AttackModule, AttackPayload, AttackSurface } from '../core/attack.js';

export interface SelectionOptions {
  only?: readonly string[];
  exclude?: readonly string[];
}

function knownFamilies(modules: readonly AttackModule[]): string[] {
  return [...new Set(modules.map((m) => m.family))].sort();
}

function resolve(
  modules: readonly AttackModule[],
  selectors: readonly string[],
  flag: string,
): Set<string> {
  const ids = new Set(modules.map((m) => m.id));
  const families = new Set<string>(modules.map((m) => m.family));
  const matched = new Set<string>();

  for (const raw of selectors) {
    const selector = raw.trim();
    if (families.has(selector)) {
      for (const m of modules) if (m.family === (selector as AttackFamily)) matched.add(m.id);
      continue;
    }
    if (ids.has(selector)) {
      matched.add(selector);
      continue;
    }
    throw new Error(
      `${flag}: unknown attack module or family "${selector}". ` +
        `Available modules: ${[...ids].join(', ')}. ` +
        `Available families: ${knownFamilies(modules).join(', ')}.`,
    );
  }
  return matched;
}

/**
 * Apply `--only` then `--exclude`, preserving registry order (so payload ids
 * stay comparable between a filtered and an unfiltered run).
 */
export function selectModules(
  modules: readonly AttackModule[],
  opts: SelectionOptions = {},
): AttackModule[] {
  let selected = [...modules];

  if (opts.only && opts.only.length > 0) {
    const keep = resolve(modules, opts.only, '--only');
    selected = selected.filter((m) => keep.has(m.id));
  }
  if (opts.exclude && opts.exclude.length > 0) {
    const drop = resolve(modules, opts.exclude, '--exclude');
    selected = selected.filter((m) => !drop.has(m.id));
  }

  if (selected.length === 0) {
    throw new Error(
      'selection is empty — --only/--exclude removed every attack module. ' +
        `Available modules: ${modules.map((m) => m.id).join(', ')}.`,
    );
  }
  return selected;
}

/** A payload predicate for `--surface`, or `undefined` when unrestricted. */
export function surfaceFilter(
  surfaces?: readonly AttackSurface[],
): ((payload: AttackPayload) => boolean) | undefined {
  if (!surfaces || surfaces.length === 0) return undefined;
  const wanted = new Set(surfaces);
  return (payload) => wanted.has(payload.surface);
}

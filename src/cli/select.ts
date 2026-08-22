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
 *   - `--defense` resolves against the WIRED default stack rather than the bare
 *     registry entries, because a control only means something once it is
 *     configured for the target under test — an output filter that does not know
 *     the canary redacts nothing. The stack is also returned in its canonical
 *     order (mark ingested content, screen the turn, filter egress, gate tools)
 *     regardless of the order the ids were typed: defenses compose, and that
 *     order is a property of the stack, not of the command line.
 */
import type { AttackFamily, AttackModule, AttackPayload, AttackSurface } from '../core/attack.js';
import type { Defense } from '../core/defense.js';
import { createDefaultDefenses, createDefenseRegistry } from '../defenses/index.js';
import type { DefenseSetOptions } from '../defenses/index.js';

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

/** Available defense ids, for help and error messages. */
export function defenseIds(): string[] {
  return createDefenseRegistry().ids();
}

/**
 * Resolve `--defense <ids|all>` into a configured stack, wired to this scan's
 * canary and forbidden tools.
 */
export function selectDefenses(
  selectors: readonly string[],
  opts: DefenseSetOptions = {},
): Defense[] {
  const stack = createDefaultDefenses(opts);
  const wanted = selectors.map((s) => s.trim()).filter((s) => s.length > 0);
  if (wanted.length === 0 || wanted.includes('all')) return stack;

  const available = new Map(stack.map((d) => [d.id, d]));
  const chosen = new Set<string>();
  for (const selector of wanted) {
    if (!available.has(selector)) {
      throw new Error(
        `--defense: unknown defense "${selector}". ` +
          `Available: ${[...available.keys()].join(', ')}, or "all" for the whole stack.`,
      );
    }
    chosen.add(selector);
  }
  // Canonical stack order, not the order the user typed them in.
  return stack.filter((d) => chosen.has(d.id));
}

/** A payload predicate for `--surface`, or `undefined` when unrestricted. */
export function surfaceFilter(
  surfaces?: readonly AttackSurface[],
): ((payload: AttackPayload) => boolean) | undefined {
  if (!surfaces || surfaces.length === 0) return undefined;
  const wanted = new Set(surfaces);
  return (payload) => wanted.has(payload.surface);
}

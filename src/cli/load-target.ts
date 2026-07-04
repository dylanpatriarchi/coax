/**
 * Loads a user-authored target module for `gauntlet scan --target <path>`.
 *
 * The module may export:
 *   - `default` — a TargetAdapter instance, or a (sync/async) factory returning one.
 *   - `createTarget` / `target` — same, as named exports.
 *   - `canary` — the secret planted in the target so the canary oracle can match.
 *   - `endpoint` — the target's URL, used ONLY by the responsible-use gate to
 *     decide whether authorization is required (non-localhost => required).
 */
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import type { TargetAdapter } from '../core/target.js';

export interface LoadedTarget {
  target: TargetAdapter;
  canary?: string;
  endpoint?: string;
}

function isAdapter(x: unknown): x is TargetAdapter {
  return (
    typeof x === 'object' &&
    x !== null &&
    typeof (x as TargetAdapter).name === 'string' &&
    typeof (x as TargetAdapter).sendMessage === 'function'
  );
}

export async function loadTarget(path: string): Promise<LoadedTarget> {
  const url = pathToFileURL(resolve(path)).href;
  const mod = (await import(url)) as Record<string, unknown>;

  const candidate = mod.default ?? mod.createTarget ?? mod.target;
  if (candidate === undefined) {
    throw new Error(
      `Target module "${path}" must export a default (or "createTarget"/"target") ` +
        'TargetAdapter or factory.',
    );
  }

  const resolved = typeof candidate === 'function' ? await (candidate as () => unknown)() : candidate;
  if (!isAdapter(resolved)) {
    throw new Error(`Target module "${path}" did not resolve to a valid TargetAdapter.`);
  }

  const out: LoadedTarget = { target: resolved };
  if (typeof mod.canary === 'string') out.canary = mod.canary;
  if (typeof mod.endpoint === 'string') out.endpoint = mod.endpoint;
  return out;
}

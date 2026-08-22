/**
 * Loads a user-authored target module for `coax scan --target <path>`.
 *
 * The module may export:
 *   - `default` — a TargetAdapter instance, or a (sync/async) factory returning one.
 *   - `createTarget` / `target` — same, as named exports.
 *   - `canary` — the secret planted in the target so the canary oracle can match.
 *   - `endpoint` — the target's URL, used ONLY by the responsible-use gate to
 *     decide whether authorization is required (non-localhost => required).
 *
 * When the export is a FACTORY we also hand back the factory itself: a scan with
 * `--concurrency > 1` needs one isolated adapter per worker (reset/inject/send
 * is a stateful transaction), and re-invoking the module's own factory is the
 * only way to get one without the adapter knowing about the runner.
 */
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import type { TargetAdapter } from '../core/target.js';

export interface LoadedTarget {
  target: TargetAdapter;
  canary?: string;
  endpoint?: string;
  /** Present only when the module exported a factory — see the note above. */
  createTarget?: () => Promise<TargetAdapter>;
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

  const resolved =
    typeof candidate === 'function' ? await (candidate as () => unknown)() : candidate;
  if (!isAdapter(resolved)) {
    throw new Error(`Target module "${path}" did not resolve to a valid TargetAdapter.`);
  }

  const out: LoadedTarget = { target: resolved };
  if (typeof candidate === 'function') {
    const factory = candidate as () => unknown;
    out.createTarget = async (): Promise<TargetAdapter> => {
      const instance = await factory();
      if (!isAdapter(instance)) {
        throw new Error(`Target module "${path}" factory did not return a valid TargetAdapter.`);
      }
      return instance;
    };
  }
  if (typeof mod.canary === 'string') out.canary = mod.canary;
  if (typeof mod.endpoint === 'string') out.endpoint = mod.endpoint;
  return out;
}

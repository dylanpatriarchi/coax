/**
 * Defense registry — the built-in controls, resolvable by stable id.
 *
 * Mirrors the attack and oracle registries so a defense set is selectable the
 * same way a suite is, and so a user-supplied control drops in beside the
 * built-ins without touching the runner. Every built-in here is a published,
 * widely-deployed mitigation implemented at its DETERMINISTIC tier: COAX's job
 * is to measure how much a control moves ASR, and a control that varied run to
 * run would make that number unattributable.
 *
 * Nothing in this directory is a product recommendation. Each module's header
 * states what it does not stop, and those limitations are carried through into
 * the rendered report.
 */
import { Registry } from '../core/registry.js';
import type { Defense } from '../core/defense.js';
import { createSpotlighting, spotlightingDefense } from './spotlighting.js';
import { createInputScreening, inputScreeningDefense } from './input-screening.js';
import { createOutputFilter, outputFilteringDefense } from './output-filtering.js';
import { createToolGuard, toolGuardDefense, HIGH_IMPACT_TOOLS } from './tool-guard.js';

/**
 * The stack in the order a request meets it: mark ingested content, screen the
 * turn, then — on the way out — filter data egress and gate tools.
 */
export const BUILTIN_DEFENSES: readonly Defense[] = [
  spotlightingDefense,
  inputScreeningDefense,
  outputFilteringDefense,
  toolGuardDefense,
];

export function createDefenseRegistry(): Registry<Defense> {
  return new Registry<Defense>('defense').registerAll(BUILTIN_DEFENSES);
}

export interface DefenseSetOptions {
  /** The planted canary, so the output filter can redact it verbatim. */
  canary?: string;
  /** Any other literal secrets the target holds. */
  secrets?: readonly string[];
  /** Tools the target declares as forbidden — denied outright. */
  forbiddenTools?: readonly string[];
  /** Tools held for human confirmation. Defaults to `HIGH_IMPACT_TOOLS`. */
  highImpactTools?: readonly string[];
  /** Hosts a tool call may legitimately reach. */
  allowedHosts?: readonly string[];
}

/**
 * Build the standard stack wired to a specific target: the canary and forbidden
 * tool list come from the scan, so the same helper produces a correctly-
 * configured control set for the mock and for a real adapter alike.
 */
export function createDefaultDefenses(opts: DefenseSetOptions = {}): Defense[] {
  const secrets = [...(opts.canary !== undefined ? [opts.canary] : []), ...(opts.secrets ?? [])];
  return [
    createSpotlighting(),
    createInputScreening(),
    createOutputFilter({
      secrets,
      ...(opts.allowedHosts !== undefined ? { allowedHosts: opts.allowedHosts } : {}),
    }),
    createToolGuard({
      deny: opts.forbiddenTools ?? [],
      requireConfirmation: opts.highImpactTools ?? HIGH_IMPACT_TOOLS,
    }),
  ];
}

export {
  spotlightingDefense,
  inputScreeningDefense,
  outputFilteringDefense,
  toolGuardDefense,
  createSpotlighting,
  createInputScreening,
  createOutputFilter,
  createToolGuard,
  HIGH_IMPACT_TOOLS,
};
export type { SpotlightingOptions } from './spotlighting.js';
export type { InputScreeningOptions, ScreeningResult } from './input-screening.js';
export { screenText } from './input-screening.js';
export type { OutputFilterOptions } from './output-filtering.js';
export type { ToolGuardOptions } from './tool-guard.js';

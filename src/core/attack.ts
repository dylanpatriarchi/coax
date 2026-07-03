/**
 * Attack module contract.
 *
 * An attack module is a parametric, seeded generator of payloads — never a raw
 * list of strings. Given an `AttackContext` (seeded RNG, the target's tools, the
 * planted canary, the attacker goal) it returns a set of `AttackPayload`s. The
 * same (seed, module) always yields the same payloads, so scans are reproducible.
 */
import { z } from 'zod';
import type { InjectedContent } from './target.js';
import type { Rng } from './rng.js';
import type { ToolSpec } from './target.js';
import type { TaxonomyId } from './taxonomy.js';

/** Broad technique family a module belongs to. */
export const AttackFamilySchema = z.enum([
  'direct-override',
  'jailbreak',
  'obfuscation',
  'indirect-injection',
  'tool-abuse',
  'exfiltration',
  'adaptive',
]);
export type AttackFamily = z.infer<typeof AttackFamilySchema>;

/** Where the payload is delivered — determines which adapter capability it needs. */
export const AttackSurfaceSchema = z.enum(['direct', 'indirect', 'tool', 'multi-turn']);
export type AttackSurface = z.infer<typeof AttackSurfaceSchema>;

export const SeveritySchema = z.enum(['low', 'medium', 'high', 'critical']);
export type Severity = z.infer<typeof SeveritySchema>;

/** A single concrete, reproducible attack instance. */
export const AttackPayloadSchema = z.object({
  /** Stable id: `${moduleId}/${variant}#${index}` — reproducible across runs. */
  id: z.string(),
  moduleId: z.string(),
  family: AttackFamilySchema,
  surface: AttackSurfaceSchema,
  severity: SeveritySchema,
  taxonomy: z.array(z.string()).min(1),
  /** The message sent to the agent via `sendMessage`. */
  message: z.string(),
  /** For indirect attacks: content staged via `injectContent` before the message. */
  inject: z
    .object({
      channel: z.enum(['web', 'document', 'tool_result', 'email']),
      source: z.string(),
      content: z.string(),
    })
    .optional(),
  /** Human-readable note on what the variant tries. */
  technique: z.string(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type AttackPayload = z.infer<typeof AttackPayloadSchema>;

/** Everything a module needs to generate payloads for a specific target/goal. */
export interface AttackContext {
  rng: Rng;
  /** The secret the exfiltration/canary oracles look for; modules may reference it. */
  canary?: string;
  /** The target's declared tools, for tool-abuse modules. */
  tools?: ToolSpec[];
  /** Free-form attacker objective, used by the adaptive module (milestone 6). */
  goal?: string;
  /** Cap on payloads a module should emit (budget control). */
  maxPayloads?: number;
}

export interface AttackModule {
  readonly id: string;
  readonly family: AttackFamily;
  readonly description: string;
  readonly taxonomy: TaxonomyId[];
  generate(ctx: AttackContext): AttackPayload[];
}

/** Convenience type for the injected-content shape (re-exported for modules). */
export type { InjectedContent };

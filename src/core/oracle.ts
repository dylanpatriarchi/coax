/**
 * Oracle contract — how COAX decides whether an attack SUCCEEDED.
 *
 * Oracles are graded by confidence:
 *   - 'deterministic': unambiguous signal (canary appeared, forbidden tool fired).
 *   - 'heuristic':     keyword/regex evidence, no model call.
 *   - 'judge':         LLM-as-judge (always paired with a deterministic fallback).
 *
 * Deterministic oracles are preferred; the false-positive suite (milestone 3)
 * measures how often each oracle fires on benign input.
 */
import { z } from 'zod';
import type { AttackPayload } from './attack.js';
import type { AgentResponse } from './target.js';

export const OracleConfidenceSchema = z.enum(['deterministic', 'heuristic', 'judge']);
export type OracleConfidence = z.infer<typeof OracleConfidenceSchema>;

export interface OracleInput {
  /** The attack that produced this response (may be a benign probe in the FP suite). */
  payload: Pick<AttackPayload, 'id' | 'family' | 'surface'> & Partial<AttackPayload>;
  response: AgentResponse;
  /** The planted secret, when the target/scan defines one. */
  canary?: string;
  /** Tool names the agent must never call, for tool-abuse oracles (milestone 5). */
  forbiddenTools?: string[];
}

export const OracleVerdictSchema = z.object({
  oracleId: z.string(),
  success: z.boolean(),
  confidence: OracleConfidenceSchema,
  /** Human-readable proof: the matched substring, tool name, or judge rationale. */
  evidence: z.string(),
});
export type OracleVerdict = z.infer<typeof OracleVerdictSchema>;

export interface Oracle {
  readonly id: string;
  readonly description: string;
  readonly confidence: OracleConfidence;
  evaluate(input: OracleInput): OracleVerdict | Promise<OracleVerdict>;
}

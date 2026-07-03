/**
 * Oracle registry. The policy (LLM-judge) oracle and the tool-abuse trace oracle
 * register here in milestones 3 and 5.
 */
import { Registry } from '../core/registry.js';
import type { Oracle } from '../core/oracle.js';
import { canaryOracle } from './canary.js';
import { policyOracle } from './policy.js';

export const BUILTIN_ORACLES: readonly Oracle[] = [canaryOracle, policyOracle];

export function createOracleRegistry(): Registry<Oracle> {
  return new Registry<Oracle>('oracle').registerAll(BUILTIN_ORACLES);
}

export { canaryOracle, policyOracle };
export { createPolicyOracle, DEFAULT_RUBRIC } from './policy.js';

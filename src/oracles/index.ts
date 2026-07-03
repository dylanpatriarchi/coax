/**
 * Oracle registry. The policy (LLM-judge) oracle and the tool-abuse trace oracle
 * register here in milestones 3 and 5.
 */
import { Registry } from '../core/registry.js';
import type { Oracle } from '../core/oracle.js';
import { canaryOracle } from './canary.js';
import { policyOracle } from './policy.js';
import { toolTraceOracle } from './tool-trace.js';

export const BUILTIN_ORACLES: readonly Oracle[] = [canaryOracle, policyOracle, toolTraceOracle];

export function createOracleRegistry(): Registry<Oracle> {
  return new Registry<Oracle>('oracle').registerAll(BUILTIN_ORACLES);
}

export { canaryOracle, policyOracle, toolTraceOracle };
export { createPolicyOracle, DEFAULT_RUBRIC } from './policy.js';

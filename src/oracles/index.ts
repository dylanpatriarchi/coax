/**
 * Oracle registry. The policy (LLM-judge) oracle and the tool-abuse trace oracle
 * register here in milestones 3 and 5.
 */
import { Registry } from '../core/registry.js';
import type { Oracle } from '../core/oracle.js';
import { canaryOracle } from './canary.js';
import { policyOracle } from './policy.js';
import { toolTraceOracle } from './tool-trace.js';
import { resourceOracle } from './resource.js';
import { egressOracle } from './egress.js';
import { codeExecOracle } from './code-exec.js';
import { trustOracle } from './trust.js';

export const BUILTIN_ORACLES: readonly Oracle[] = [
  canaryOracle,
  policyOracle,
  toolTraceOracle,
  resourceOracle,
  egressOracle,
  codeExecOracle,
  trustOracle,
];

export function createOracleRegistry(): Registry<Oracle> {
  return new Registry<Oracle>('oracle').registerAll(BUILTIN_ORACLES);
}

export { canaryOracle, policyOracle, toolTraceOracle, resourceOracle, egressOracle, codeExecOracle, trustOracle };
export { createPolicyOracle, DEFAULT_RUBRIC } from './policy.js';
export { createResourceOracle } from './resource.js';
export { createTrustOracle } from './trust.js';

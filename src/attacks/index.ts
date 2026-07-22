/**
 * Attack registry — the built-in attack modules and helpers to generate payloads
 * from a selected suite. New modules (indirect injection, tool abuse, adaptive)
 * register here in later milestones.
 */
import { Registry } from '../core/registry.js';
import type { AttackContext, AttackModule, AttackPayload } from '../core/attack.js';
import { directOverrideModule } from './direct-override.js';
import { jailbreakModule } from './jailbreak.js';
import { obfuscationModule } from './obfuscation.js';
import { indirectInjectionModule } from './indirect-injection.js';
import { toolAbuseModule } from './tool-abuse.js';
import { goalHijackModule } from './goal-hijack.js';
import { supplyChainModule } from './supply-chain.js';
import { unboundedConsumptionModule } from './unbounded-consumption.js';
import { codeExecutionModule } from './code-execution.js';
import { manyShotJailbreakModule } from './many-shot-jailbreak.js';
import { skeletonKeyModule } from './skeleton-key.js';
import { policyPuppetryModule } from './policy-puppetry.js';

export const BUILTIN_ATTACKS: readonly AttackModule[] = [
  directOverrideModule,
  jailbreakModule,
  obfuscationModule,
  indirectInjectionModule,
  toolAbuseModule,
  // Agentic (OWASP ASI 2026) single-turn modules.
  goalHijackModule,
  supplyChainModule,
  unboundedConsumptionModule,
  codeExecutionModule,
  // Frontier (2024-2025 published) jailbreak/override techniques.
  manyShotJailbreakModule,
  skeletonKeyModule,
  policyPuppetryModule,
];

export function createAttackRegistry(): Registry<AttackModule> {
  return new Registry<AttackModule>('attack').registerAll(BUILTIN_ATTACKS);
}

/**
 * Generate the full payload set for a list of modules under one context.
 * Deterministic: identical (seed, modules, context) always yields identical output.
 */
export function generatePayloads(
  modules: readonly AttackModule[],
  ctx: AttackContext,
): AttackPayload[] {
  return modules.flatMap((m) => m.generate(ctx));
}

export {
  directOverrideModule,
  jailbreakModule,
  obfuscationModule,
  indirectInjectionModule,
  toolAbuseModule,
  goalHijackModule,
  supplyChainModule,
  unboundedConsumptionModule,
  codeExecutionModule,
  manyShotJailbreakModule,
  skeletonKeyModule,
  policyPuppetryModule,
};

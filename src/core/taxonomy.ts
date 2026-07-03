/**
 * Taxonomy mapping — OWASP LLM Top 10 (2025) plus a couple of agent-security
 * categories. Every attack payload is tagged with one or more of these ids so
 * the final report can group findings by recognised category.
 */

export const OWASP_LLM = {
  LLM01: 'LLM01: Prompt Injection',
  LLM02: 'LLM02: Sensitive Information Disclosure',
  LLM04: 'LLM04: Data and Model Poisoning',
  LLM05: 'LLM05: Improper Output Handling',
  LLM06: 'LLM06: Excessive Agency',
  LLM07: 'LLM07: System Prompt Leakage',
  LLM08: 'LLM08: Vector and Embedding Weaknesses',
  LLM09: 'LLM09: Misinformation',
  LLM10: 'LLM10: Unbounded Consumption',
} as const;

export type TaxonomyId = keyof typeof OWASP_LLM;

export function taxonomyLabel(id: TaxonomyId): string {
  return OWASP_LLM[id];
}

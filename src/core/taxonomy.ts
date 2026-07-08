/**
 * Taxonomy mapping across the three vocabularies a 2026 agent red-team report is
 * expected to speak:
 *
 *   - OWASP LLM Top 10 (2025)              — model/prompt-level risks (LLM01…LLM10)
 *   - OWASP Top 10 for Agentic Apps (2026) — agent/orchestration risks (ASI01…ASI10)
 *   - MITRE ATLAS                          — adversarial technique IDs (AML.Txxxx)
 *
 * Every attack payload / scenario is tagged with one or more ids drawn from any
 * of these, so the report can roll findings up per recognised category. The
 * ATLAS mapping is deliberately CONSERVATIVE: only well-established technique ids
 * are listed, and a payload is only tagged with one when the mapping is clear.
 */

/** OWASP Top 10 for LLM Applications (2025). */
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

/** OWASP Top 10 for Agentic Applications (2026) — the agent-specific layer. */
export const OWASP_ASI = {
  ASI01: 'ASI01: Agent Goal Hijack',
  ASI02: 'ASI02: Tool Misuse & Exploitation',
  ASI03: 'ASI03: Agent Identity & Privilege Abuse',
  ASI04: 'ASI04: Agentic Supply Chain Compromise',
  ASI05: 'ASI05: Unexpected Code Execution',
  ASI06: 'ASI06: Memory & Context Poisoning',
  ASI07: 'ASI07: Insecure Inter-Agent Communication',
  ASI08: 'ASI08: Cascading Agent Failures',
  ASI09: 'ASI09: Human-Agent Trust Exploitation',
  ASI10: 'ASI10: Rogue Agents',
} as const;

/**
 * MITRE ATLAS technique ids. Only stable, high-confidence ids are included so we
 * never mislabel a finding with a fabricated technique number.
 */
export const MITRE_ATLAS = {
  'AML.T0051': 'AML.T0051: LLM Prompt Injection',
  'AML.T0054': 'AML.T0054: LLM Jailbreak',
  'AML.T0053': 'AML.T0053: LLM Plugin Compromise',
  'AML.T0057': 'AML.T0057: LLM Data Leakage',
  'AML.T0020': 'AML.T0020: Poison Training Data',
  'AML.T0024': 'AML.T0024: Exfiltration via ML Inference API',
  'AML.T0055': 'AML.T0055: Unsecured Credentials',
} as const;

export type OwaspLlmId = keyof typeof OWASP_LLM;
export type OwaspAsiId = keyof typeof OWASP_ASI;
export type AtlasId = keyof typeof MITRE_ATLAS;

/** Any id an attack/scenario may tag itself with. */
export type TaxonomyId = OwaspLlmId | OwaspAsiId | AtlasId;

/** Which vocabulary an id belongs to — drives per-scheme report rollups. */
export type TaxonomyScheme = 'owasp-llm' | 'owasp-asi' | 'mitre-atlas' | 'unknown';

const ALL_LABELS: Record<string, string> = { ...OWASP_LLM, ...OWASP_ASI, ...MITRE_ATLAS };

/** Human-readable label for any tag; falls back to the raw id if unknown. */
export function taxonomyLabel(id: string): string {
  return ALL_LABELS[id] ?? id;
}

/** Classify a tag into its scheme so reports can group by vocabulary. */
export function taxonomyScheme(id: string): TaxonomyScheme {
  if (id in OWASP_LLM) return 'owasp-llm';
  if (id in OWASP_ASI) return 'owasp-asi';
  if (id in MITRE_ATLAS) return 'mitre-atlas';
  return 'unknown';
}

const SCHEME_LABEL: Record<TaxonomyScheme, string> = {
  'owasp-llm': 'OWASP LLM Top 10 (2025)',
  'owasp-asi': 'OWASP Agentic Top 10 (2026)',
  'mitre-atlas': 'MITRE ATLAS',
  unknown: 'Other',
};

export function schemeLabel(scheme: TaxonomyScheme): string {
  return SCHEME_LABEL[scheme];
}

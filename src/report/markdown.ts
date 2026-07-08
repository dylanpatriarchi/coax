/**
 * Markdown report renderer. Deterministic given a `ScanReport`; an optional
 * `generatedAt` string is the only non-reproducible input and appears solely in
 * a footer, never in the scored tables.
 */
import type { ScanReport, Finding, CategoryScore, TaxonomyScore } from './scoring.js';

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

function categoryTable(title: string, rows: CategoryScore[]): string {
  const head = `| ${title} | ASR | Hits | Total |\n| --- | ---: | ---: | ---: |`;
  const body = rows
    .map((r) => `| ${r.key} | ${pct(r.asr)} | ${r.hits} | ${r.total} |`)
    .join('\n');
  return `${head}\n${body}`;
}

function taxonomyTable(rows: TaxonomyScore[], title = 'Category'): string {
  const head = `| ${title} | ASR | Hits | Total |\n| --- | ---: | ---: | ---: |`;
  const body = rows.map((r) => `| ${r.label} | ${pct(r.asr)} | ${r.hits} | ${r.total} |`).join('\n');
  return `${head}\n${body}`;
}

function fence(content: string): string {
  // Avoid breaking out of the code fence if the payload contains backticks.
  const fenceMark = content.includes('```') ? '````' : '```';
  return `${fenceMark}\n${content}\n${fenceMark}`;
}

function findingSection(f: Finding, index: number): string {
  const parts: string[] = [];
  parts.push(`### ${index + 1}. \`${f.payloadId}\` — ${f.severity.toUpperCase()}`);
  parts.push('');
  parts.push(
    `- **Family:** ${f.family}  •  **Surface:** ${f.surface}  •  **Technique:** ${f.technique}`,
  );
  parts.push(`- **Taxonomy:** ${f.taxonomy.join(', ')}`);
  parts.push(
    `- **Detected by:** ${f.firedOracles.map((o) => `\`${o.oracleId}\` (${o.evidence})`).join('; ')}`,
  );
  parts.push('');
  parts.push('**Reproducible transcript**');
  parts.push('');
  if (f.inject) {
    parts.push(`_Injected via ${f.inject.channel} (source: ${f.inject.source}):_`);
    parts.push(fence(f.inject.content));
  }
  parts.push('_User message:_');
  parts.push(fence(f.message));
  parts.push('_Agent output:_');
  parts.push(fence(f.output || '(no text output)'));
  if (f.toolCalls.length > 0) {
    parts.push('_Tool calls:_');
    parts.push(fence(f.toolCalls.map((c) => `${c.name}(${JSON.stringify(c.arguments)})`).join('\n')));
  }
  parts.push('');
  parts.push(`> **Remediation:** ${f.remediation}`);
  return parts.join('\n');
}

export interface RenderOptions {
  generatedAt?: string;
}

export function renderMarkdown(report: ScanReport, opts: RenderOptions = {}): string {
  const s: string[] = [];
  s.push('# COAX robustness report');
  s.push('');
  s.push(
    '> Defensive testing artifact. Run only against systems you own or are authorized to test.',
  );
  s.push('');
  s.push(
    `**Target:** \`${report.meta.target}\`  •  **Seed:** ${report.meta.seed}  •  ` +
      `**Attacks:** ${report.meta.attackCount}  •  **Successful:** ${report.meta.successCount}`,
  );
  s.push('');
  s.push('## Summary');
  s.push('');
  s.push(
    `- **Overall ASR:** ${pct(report.overall.asr)} (${report.overall.hits}/${report.overall.total})`,
  );
  s.push(`- **Severity-weighted ASR:** ${pct(report.overall.weightedAsr)}`);
  if (report.falsePositive) {
    s.push(
      `- **Oracle false-positive rate:** ${pct(report.falsePositive.overallRate)} ` +
        `(lower is better; measured on ${report.falsePositive.total} benign inputs)`,
    );
  }
  s.push('');
  s.push('## ASR by attack family');
  s.push('');
  s.push(categoryTable('Family', report.byFamily));
  s.push('');
  s.push('## ASR by surface');
  s.push('');
  s.push(categoryTable('Surface', report.bySurface));
  s.push('');
  const llm = report.byTaxonomy.filter((t) => t.scheme === 'owasp-llm');
  const asi = report.byTaxonomy.filter((t) => t.scheme === 'owasp-asi');
  const atlas = report.byTaxonomy.filter((t) => t.scheme === 'mitre-atlas');

  s.push('## ASR by OWASP LLM Top 10 category');
  s.push('');
  s.push(taxonomyTable(llm, 'OWASP LLM category'));
  s.push('');
  if (asi.length > 0) {
    s.push('## ASR by OWASP Agentic Top 10 (2026)');
    s.push('');
    s.push(taxonomyTable(asi, 'Agentic category'));
    s.push('');
  }
  if (atlas.length > 0) {
    s.push('## ASR by MITRE ATLAS technique');
    s.push('');
    s.push(taxonomyTable(atlas, 'ATLAS technique'));
    s.push('');
  }
  const otherTax = report.byTaxonomy.filter(
    (t) => t.scheme !== 'owasp-llm' && t.scheme !== 'owasp-asi' && t.scheme !== 'mitre-atlas',
  );
  if (otherTax.length > 0) {
    s.push('## ASR by other tags');
    s.push('');
    s.push(taxonomyTable(otherTax, 'Tag'));
    s.push('');
  }

  if (report.utility) {
    const u = report.utility;
    s.push('## Utility (usefulness vs. security)');
    s.push('');
    s.push(`- **Benign task completion:** ${pct(u.benign.rate)} (${u.benign.passed}/${u.benign.total})`);
    s.push(
      `- **Utility under attack:** ${pct(u.underAttack.rate)} ` +
        `(${u.underAttack.passed}/${u.underAttack.total} both completed the task AND resisted; ` +
        `${u.underAttack.compromised} compromised)`,
    );
    s.push('');
  }

  if (report.falsePositive) {
    s.push('## Oracle false-positive rates');
    s.push('');
    s.push('| Oracle | FP rate | False positives | Benign inputs |');
    s.push('| --- | ---: | ---: | ---: |');
    for (const o of report.falsePositive.perOracle) {
      s.push(`| ${o.oracleId} | ${pct(o.rate)} | ${o.falsePositives} | ${o.total} |`);
    }
    s.push('');
  }

  s.push('## Findings');
  s.push('');
  if (report.findings.length === 0) {
    s.push('_No successful attacks — the target resisted every payload in this suite._');
  } else {
    s.push(report.findings.map(findingSection).join('\n\n---\n\n'));
  }
  s.push('');
  if (opts.generatedAt) {
    s.push('---');
    s.push(`_Generated ${opts.generatedAt} by COAX. Report is reproducible from the seed above._`);
  }
  return s.join('\n');
}

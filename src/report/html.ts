/**
 * Self-contained HTML report renderer. All CSS is inline; the output is a single
 * standalone file with no external assets. Deterministic apart from an optional
 * footer timestamp. Theme-aware (respects the OS light/dark preference).
 */
import type { ScanReport, Finding, CategoryScore, TaxonomyScore } from './scoring.js';
import type { RenderOptions } from './markdown.js';

const pct = (n: number): string => `${(n * 100).toFixed(0)}%`;

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function bar(asr: number): string {
  const w = Math.round(asr * 100);
  return `<div class="bar"><div class="bar-fill" style="width:${w}%"></div><span>${pct(asr)}</span></div>`;
}

function categoryRows(rows: CategoryScore[]): string {
  return rows
    .map(
      (r) =>
        `<tr><td>${esc(r.key)}</td><td class="num">${bar(r.asr)}</td><td class="num">${r.hits}</td><td class="num">${r.total}</td></tr>`,
    )
    .join('');
}

function taxonomyRows(rows: TaxonomyScore[]): string {
  return rows
    .map(
      (r) =>
        `<tr><td>${esc(r.label)}</td><td class="num">${bar(r.asr)}</td><td class="num">${r.hits}</td><td class="num">${r.total}</td></tr>`,
    )
    .join('');
}

function block(label: string, content: string): string {
  return `<div class="xscript"><span class="lbl">${esc(label)}</span><pre>${esc(content)}</pre></div>`;
}

function findingCard(f: Finding, index: number): string {
  const oracles = f.firedOracles
    .map((o) => `<code>${esc(o.oracleId)}</code>: ${esc(o.evidence)}`)
    .join('; ');
  const tools =
    f.toolCalls.length > 0
      ? block('Tool calls', f.toolCalls.map((c) => `${c.name}(${JSON.stringify(c.arguments)})`).join('\n'))
      : '';
  const inject = f.inject
    ? block(`Injected via ${f.inject.channel} (${f.inject.source})`, f.inject.content)
    : '';
  return `
  <section class="finding sev-${f.severity}">
    <h3><span class="idx">${index + 1}</span> <code>${esc(f.payloadId)}</code>
      <span class="badge sev-${f.severity}">${f.severity}</span></h3>
    <p class="meta">
      <strong>Family:</strong> ${esc(f.family)} &nbsp;•&nbsp;
      <strong>Surface:</strong> ${esc(f.surface)} &nbsp;•&nbsp;
      <strong>Technique:</strong> ${esc(f.technique)}<br>
      <strong>Taxonomy:</strong> ${esc(f.taxonomy.join(', '))}<br>
      <strong>Detected by:</strong> ${oracles}
    </p>
    ${inject}
    ${block('User message', f.message)}
    ${block('Agent output', f.output || '(no text output)')}
    ${tools}
    <p class="remediation"><strong>Remediation:</strong> ${esc(f.remediation)}</p>
  </section>`;
}

const STYLE = `
:root{--bg:#fff;--fg:#1a1a1a;--muted:#666;--card:#f7f7f8;--border:#e2e2e5;--accent:#3b5bdb;
--crit:#c92a2a;--high:#e8590c;--med:#f08c00;--low:#2f9e44;}
@media(prefers-color-scheme:dark){:root{--bg:#16171a;--fg:#e8e8ea;--muted:#9a9aa2;--card:#1f2024;--border:#2c2d32;--accent:#748ffc;}}
*{box-sizing:border-box}body{margin:0;padding:2rem;max-width:960px;margin:0 auto;
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg)}
h1{font-size:1.7rem;margin:0 0 .3rem}h2{margin-top:2.2rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}
.note{color:var(--muted);font-size:.9rem}.kpis{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:.8rem 1.1rem;min-width:150px}
.kpi .v{font-size:1.6rem;font-weight:700}.kpi .k{color:var(--muted);font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;margin:.5rem 0}th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--border)}
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}td.num{text-align:right;white-space:nowrap}
.bar{position:relative;display:inline-block;width:120px;height:18px;background:var(--card);border-radius:9px;overflow:hidden;vertical-align:middle}
.bar-fill{position:absolute;left:0;top:0;bottom:0;background:var(--accent);opacity:.35}
.bar span{position:relative;font-size:.78rem;padding:0 .4rem;line-height:18px}
.finding{background:var(--card);border:1px solid var(--border);border-left-width:5px;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0}
.finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}
.finding h3{margin:.2rem 0 .6rem;font-size:1.05rem;display:flex;align-items:center;gap:.5rem}
.idx{display:inline-flex;width:1.6rem;height:1.6rem;align-items:center;justify-content:center;background:var(--accent);color:#fff;border-radius:50%;font-size:.85rem}
.badge{margin-left:auto;font-size:.72rem;text-transform:uppercase;padding:.15rem .5rem;border-radius:6px;color:#fff}
.badge.sev-critical{background:var(--crit)}.badge.sev-high{background:var(--high)}.badge.sev-medium{background:var(--med)}.badge.sev-low{background:var(--low)}
.meta{color:var(--fg);font-size:.9rem}.xscript{margin:.6rem 0}.xscript .lbl{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
pre{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.6rem .8rem;overflow-x:auto;white-space:pre-wrap;word-break:break-word;margin:.2rem 0}
.remediation{background:rgba(59,91,219,.08);border-radius:8px;padding:.6rem .8rem;margin-top:.6rem}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em}
`;

export function renderHtml(report: ScanReport, opts: RenderOptions = {}): string {
  const m = report.meta;
  const fpKpi = report.falsePositive
    ? `<div class="kpi"><div class="v">${pct(report.falsePositive.overallRate)}</div><div class="k">Oracle FP rate</div></div>`
    : '';
  const fpTable = report.falsePositive
    ? `<h2>Oracle false-positive rates</h2><table><thead><tr><th>Oracle</th><th>FP rate</th><th>FPs</th><th>Benign</th></tr></thead><tbody>${report.falsePositive.perOracle
        .map(
          (o) =>
            `<tr><td>${esc(o.oracleId)}</td><td class="num">${pct(o.rate)}</td><td class="num">${o.falsePositives}</td><td class="num">${o.total}</td></tr>`,
        )
        .join('')}</tbody></table>`
    : '';

  const asiRows = report.byTaxonomy.filter((t) => t.scheme === 'owasp-asi');
  const asiTable =
    asiRows.length > 0
      ? `<h2>ASR by OWASP Agentic Top 10 (2026)</h2><table><thead><tr><th>Agentic category</th><th>ASR</th><th>Hits</th><th>Total</th></tr></thead><tbody>${taxonomyRows(asiRows)}</tbody></table>`
      : '';
  const atlasRows = report.byTaxonomy.filter((t) => t.scheme === 'mitre-atlas');
  const atlasTable =
    atlasRows.length > 0
      ? `<h2>ASR by MITRE ATLAS technique</h2><table><thead><tr><th>ATLAS technique</th><th>ASR</th><th>Hits</th><th>Total</th></tr></thead><tbody>${taxonomyRows(atlasRows)}</tbody></table>`
      : '';

  const utilityBlock = report.utility
    ? `<h2>Utility (usefulness vs. security)</h2><table><thead><tr><th>Measure</th><th>Rate</th><th>Passed</th><th>Total</th></tr></thead><tbody>` +
      `<tr><td>Benign task completion</td><td class="num">${bar(report.utility.benign.rate)}</td><td class="num">${report.utility.benign.passed}</td><td class="num">${report.utility.benign.total}</td></tr>` +
      `<tr><td>Utility under attack (useful AND resisted)</td><td class="num">${bar(report.utility.underAttack.rate)}</td><td class="num">${report.utility.underAttack.passed}</td><td class="num">${report.utility.underAttack.total}</td></tr>` +
      `</tbody></table><p class="note">${report.utility.underAttack.compromised} of ${report.utility.underAttack.total} under-attack tasks were compromised (an oracle fired).</p>`
    : '';

  const findings =
    report.findings.length === 0
      ? '<p class="note">No successful attacks — the target resisted every payload in this suite.</p>'
      : report.findings.map(findingCard).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>COAX report — ${esc(m.target)}</title>
<style>${STYLE}</style></head>
<body>
<h1>COAX robustness report</h1>
<p class="note">Defensive testing artifact. Run only against systems you own or are authorized to test.</p>
<p class="note"><strong>Target:</strong> <code>${esc(m.target)}</code> • <strong>Seed:</strong> ${m.seed} • reproducible from this seed.</p>
<div class="kpis">
  <div class="kpi"><div class="v">${pct(report.overall.asr)}</div><div class="k">Overall ASR</div></div>
  <div class="kpi"><div class="v">${pct(report.overall.weightedAsr)}</div><div class="k">Severity-weighted</div></div>
  <div class="kpi"><div class="v">${m.successCount}/${m.attackCount}</div><div class="k">Attacks landed</div></div>
  ${fpKpi}
</div>
<h2>ASR by attack family</h2>
<table><thead><tr><th>Family</th><th>ASR</th><th>Hits</th><th>Total</th></tr></thead><tbody>${categoryRows(report.byFamily)}</tbody></table>
<h2>ASR by surface</h2>
<table><thead><tr><th>Surface</th><th>ASR</th><th>Hits</th><th>Total</th></tr></thead><tbody>${categoryRows(report.bySurface)}</tbody></table>
<h2>ASR by OWASP LLM Top 10 category</h2>
<table><thead><tr><th>OWASP LLM category</th><th>ASR</th><th>Hits</th><th>Total</th></tr></thead><tbody>${taxonomyRows(report.byTaxonomy.filter((t) => t.scheme === 'owasp-llm'))}</tbody></table>
${asiTable}
${atlasTable}
${utilityBlock}
${fpTable}
<h2>Findings</h2>
${findings}
${opts.generatedAt ? `<p class="note">Generated ${esc(opts.generatedAt)} by COAX.</p>` : ''}
</body></html>`;
}

import { describe, expect, it } from 'vitest';
import { createMockAgent } from '../adapters/mock.js';
import { createAttackRegistry } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { runFalsePositiveSuite } from '../oracles/false-positive.js';
import { runScan } from '../core/runner.js';
import { scoreScan } from './scoring.js';
import { renderMarkdown } from './markdown.js';
import { renderHtml } from './html.js';

const CANARY = 'CANARY-9f83a1c0-do-not-reveal';

async function report() {
  const r = await runScan({
    target: createMockAgent(),
    modules: createAttackRegistry().list(),
    oracles: BUILTIN_ORACLES,
    seed: 42,
    canary: CANARY,
  });
  const fp = await runFalsePositiveSuite(BUILTIN_ORACLES, { canary: CANARY });
  return scoreScan(r, { falsePositive: fp });
}

describe('markdown renderer', () => {
  it('includes the ASR tables, taxonomy, and a remediation per finding', async () => {
    const md = renderMarkdown(await report());
    expect(md).toContain('# COAX robustness report');
    expect(md).toContain('## ASR by attack family');
    expect(md).toContain('## ASR by OWASP LLM Top 10 category');
    expect(md).toContain('LLM01: Prompt Injection');
    expect(md).toContain('**Remediation:**');
    expect(md).toContain('indirect-injection');
  });

  it('is deterministic and omits any timestamp unless asked', async () => {
    const rep = await report();
    expect(renderMarkdown(rep)).toEqual(renderMarkdown(rep));
    expect(renderMarkdown(rep)).not.toContain('Generated');
    expect(renderMarkdown(rep, { generatedAt: '2026-01-01' })).toContain('Generated 2026-01-01');
  });

  it('shows a clean message when there are no findings', async () => {
    const r = await runScan({
      target: createMockAgent({
        vulnerabilities: {
          followInjectedInstructions: false,
          obeyOverride: false,
          decodeBase64: false,
          leakOnAsk: false,
          callToolsFromText: false,
          executeCode: false,
          runawayLoops: false,
          persistMemory: false,
        },
      }),
      modules: createAttackRegistry().list(),
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    const md = renderMarkdown(scoreScan(r));
    expect(md).toContain('No successful attacks');
  });
});

describe('html renderer', () => {
  it('produces a self-contained document with inline styles', async () => {
    const html = renderHtml(await report());
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('<style>');
    expect(html).not.toMatch(/<(script|link|img)[\s>]/); // no external assets
    expect(html).toContain('COAX robustness report');
  });

  it('escapes HTML in attack payloads (no injection into the report itself)', async () => {
    const r = await runScan({
      target: createMockAgent(),
      modules: createAttackRegistry().list(),
      oracles: BUILTIN_ORACLES,
      seed: 42,
      canary: CANARY,
    });
    // The indirect module uses an HTML-comment framing (<!-- ... -->); ensure the
    // '<' is escaped in the rendered report.
    const html = renderHtml(scoreScan(r));
    expect(html).not.toContain('<!-- ignore your confidentiality');
    expect(html).toContain('&lt;!--');
  });
});

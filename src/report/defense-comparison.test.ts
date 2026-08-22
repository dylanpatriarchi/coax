import { describe, expect, it } from 'vitest';
import { createMockAgent, MockConfigSchema } from '../adapters/mock.js';
import { BUILTIN_ATTACKS } from '../attacks/index.js';
import { BUILTIN_ORACLES } from '../oracles/index.js';
import { block } from '../core/defense.js';
import type { Defense } from '../core/defense.js';
import { createDefaultDefenses } from '../defenses/index.js';
import { compareDefenses } from './defense-comparison.js';
import { scoreScan } from './scoring.js';
import { renderHtml } from './html.js';
import { renderMarkdown } from './markdown.js';

const CANARY = MockConfigSchema.parse({}).canary;
const FORBIDDEN = ['send_email', 'delete_file', 'run_code', 'fetch_url'];

const scanOpts = () => ({
  target: createMockAgent(),
  modules: BUILTIN_ATTACKS,
  oracles: BUILTIN_ORACLES,
  seed: 42,
  canary: CANARY,
});

const defaultStack = (): Defense[] =>
  createDefaultDefenses({ canary: CANARY, forbiddenTools: FORBIDDEN });

async function standardComparison() {
  return compareDefenses({
    ...scanOpts(),
    defenses: defaultStack(),
    utility: { canary: CANARY, forbiddenTools: FORBIDDEN },
    utilityTarget: () => createMockAgent(),
  });
}

describe('compareDefenses', () => {
  it('produces a baseline-vs-defended number per family, with a residual', async () => {
    const { comparison } = await standardComparison();

    expect(comparison.overall.baseline.rate).toBeGreaterThan(0.8);
    expect(comparison.overall.defended.rate).toBeLessThan(0.3);
    expect(comparison.overall.reduction).toBeGreaterThan(0.7);
    expect(comparison.overall.residual).toBe(comparison.overall.defended.rate);

    for (const f of comparison.byFamily) {
      expect(f.defended.trials).toBe(f.baseline.trials);
      expect(f.residual).toBe(f.defended.rate);
      expect(f.reduction).toBeGreaterThanOrEqual(0);
      expect(f.reduction).toBeLessThanOrEqual(1);
    }

    const toolAbuse = comparison.byFamily.find((f) => f.key === 'tool-abuse');
    expect(toolAbuse?.baseline.rate).toBe(1);
    expect(toolAbuse?.residual).toBe(0);
  });

  it('reports intervals on both columns', async () => {
    const { comparison } = await standardComparison();
    expect(comparison.overall.baseline.lo).toBeLessThan(comparison.overall.baseline.rate);
    expect(comparison.overall.baseline.hi).toBeGreaterThan(comparison.overall.baseline.rate);
    expect(comparison.overall.defended.hi).toBeGreaterThan(comparison.overall.defended.rate);
  });

  it('names every control and what it does not stop', async () => {
    const { comparison } = await standardComparison();
    expect(comparison.defenses.map((d) => d.id)).toEqual([
      'spotlighting',
      'input-screening',
      'output-filtering',
      'tool-guard',
    ]);
    for (const d of comparison.defenses) expect(d.limitations.length).toBeGreaterThan(40);
  });

  it('accounts for what the stack actually did, so a block is never a silent miss', async () => {
    const { comparison } = await standardComparison();
    expect(comparison.activity.totalAttempts).toBeGreaterThan(0);
    expect(comparison.activity.blockedAttempts).toBeGreaterThan(0);
    expect(comparison.activity.quarantinedIngests).toBeGreaterThan(0);
    expect(comparison.activity.blockedAttempts).toBeLessThanOrEqual(
      comparison.activity.totalAttempts,
    );
  });

  it('measures utility on the DEFENDED target too', async () => {
    const { comparison } = await standardComparison();
    expect(comparison.utility).toBeDefined();
    // The real stack keeps benign work intact while closing the injection paths.
    expect(comparison.utility!.defended.benign.rate).toBe(1);
    expect(comparison.utility!.baseline.underAttack.rate).toBe(0);
    expect(comparison.utility!.defended.underAttack.rate).toBe(1);
  });

  it('punishes a control that just blocks everything', async () => {
    const refuseAll: Defense = {
      id: 'refuse-all',
      description: 'refuses every request',
      limitations: 'being useful in any way whatsoever, which is the entire point of this test',
      screenInput: (input) => block(input, 'refused'),
    };
    const { comparison } = await compareDefenses({
      ...scanOpts(),
      defenses: [refuseAll],
      utility: { canary: CANARY, forbiddenTools: FORBIDDEN },
      utilityTarget: () => createMockAgent(),
    });

    // A perfect security score...
    expect(comparison.overall.defended.rate).toBe(0);
    expect(comparison.overall.residual).toBe(0);
    // ...and a completely broken agent, visible in the same report.
    expect(comparison.utility!.baseline.benign.rate).toBe(1);
    expect(comparison.utility!.defended.benign.rate).toBe(0);
    expect(comparison.activity.blockedAttempts).toBe(comparison.activity.totalAttempts);
  });

  it('can skip the utility suite when asked', async () => {
    const { comparison } = await compareDefenses({
      ...scanOpts(),
      defenses: defaultStack(),
      utility: false,
    });
    expect(comparison.utility).toBeUndefined();
  });

  it('reuses a supplied baseline instead of scanning twice', async () => {
    const opts = scanOpts();
    let sends = 0;
    const counting = {
      ...opts.target,
      name: opts.target.name,
      sendMessage: async (input: { message: string }) => {
        sends += 1;
        return opts.target.sendMessage(input);
      },
      injectContent: opts.target.injectContent.bind(opts.target),
      describeTools: opts.target.describeTools.bind(opts.target),
      reset: opts.target.reset.bind(opts.target),
    };

    const withBaseline = await compareDefenses({
      ...opts,
      target: counting,
      defenses: defaultStack(),
      utility: false,
    });
    const oneScan = sends;
    sends = 0;
    await compareDefenses({
      ...opts,
      target: counting,
      defenses: defaultStack(),
      baseline: withBaseline.baseline,
      utility: false,
    });
    expect(sends).toBeLessThan(oneScan);
  });

  it('is deterministic for a fixed seed', async () => {
    const a = await standardComparison();
    const b = await standardComparison();
    expect(b.comparison).toEqual(a.comparison);
  });
});

describe('rendering the comparison', () => {
  it('shows baseline, defended, reduction and residual in markdown', async () => {
    const { baseline, comparison } = await standardComparison();
    const md = renderMarkdown(scoreScan(baseline, { defense: comparison }));
    expect(md).toContain('## Defense effectiveness');
    expect(md).toContain('| Family | Baseline ASR | Defended ASR | Reduction | Residual |');
    expect(md).toContain('tool-guard');
    expect(md).toContain('_Does not stop:_');
    expect(md).toContain('residual');
  });

  it('shows the same in HTML, still self-contained and escaped', async () => {
    const { baseline, comparison } = await standardComparison();
    const html = renderHtml(scoreScan(baseline, { defense: comparison }));
    expect(html).toContain('Defense effectiveness');
    expect(html).toContain('Residual risk');
    expect(html).toContain('Does not stop:');
    expect(html).not.toMatch(/<(script|link|img)[\s>]/);
  });

  it('omits the section entirely when no defense was measured', async () => {
    const { baseline } = await standardComparison();
    const md = renderMarkdown(scoreScan(baseline));
    expect(md).not.toContain('## Defense effectiveness');
  });

  it('renders the confidence interval alongside every ASR', async () => {
    const { baseline } = await standardComparison();
    const md = renderMarkdown(scoreScan(baseline));
    expect(md).toContain('95% CI');
    expect(md).toMatch(/Overall ASR:\*\* \d+% \[\d+%, \d+%\]/);
  });
});

/**
 * Playwright headless-browser adapter for web-acting agents.
 *
 * Drives an agent that lives behind a web UI: it types the attack into an input,
 * submits, and reads the agent's rendered reply. Indirect injection is delivered
 * by intercepting the agent's own network fetch of a configured "ingest" URL and
 * serving poisoned content in its place — simulating a compromised page/document
 * the agent retrieves.
 *
 * `playwright` is an OPTIONAL dependency, loaded lazily via a non-literal import
 * so it is neither resolved by `tsc` nor required by offline CI. Install it only
 * when you need this adapter:
 *   npm i -D playwright && npx playwright install chromium
 */
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
} from '../core/target.js';

export interface PlaywrightAdapterConfig {
  /** URL of the agent's web UI. */
  url: string;
  /** CSS selector for the message input. */
  inputSelector: string;
  /** CSS selector for the send/submit control. */
  submitSelector: string;
  /** CSS selector for the element that contains the agent's reply. */
  outputSelector: string;
  /** When the agent fetches a URL matching this, serve staged poisoned content. */
  ingestUrlPattern?: string | RegExp;
  /** MIME type used when fulfilling the intercepted ingest request. */
  ingestContentType?: string;
  headless?: boolean;
  timeoutMs?: number;
}

async function loadPlaywright(): Promise<{ chromium: { launch: (o: unknown) => Promise<unknown> } }> {
  const pkg = 'playwright';
  try {
    // Non-literal specifier: tsc will not try to resolve it, so the package can
    // be absent in CI without breaking the build.
    return (await import(pkg)) as { chromium: { launch: (o: unknown) => Promise<unknown> } };
  } catch {
    throw new Error(
      "Playwright adapter requires the optional 'playwright' package. Install it with: " +
        'npm i -D playwright && npx playwright install chromium',
    );
  }
}

/* The browser objects are untyped here (playwright types aren't installed). */
/* eslint-disable @typescript-eslint/no-explicit-any */
export class PlaywrightAgent implements TargetAdapter {
  readonly name: string;
  private staged: InjectedContent[] = [];
  private browser: any;

  constructor(private readonly cfg: PlaywrightAdapterConfig) {
    if (!cfg.url) throw new Error('PlaywrightAgent: url is required');
    this.name = `playwright:${cfg.url}`;
  }

  async injectContent(content: InjectedContent): Promise<void> {
    this.staged.push(content);
  }

  async reset(): Promise<void> {
    this.staged = [];
  }

  private async ensureBrowser(): Promise<void> {
    if (this.browser) return;
    const { chromium } = await loadPlaywright();
    this.browser = await chromium.launch({ headless: this.cfg.headless ?? true });
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    await this.ensureBrowser();
    const context = await this.browser.newContext();
    const page = await context.newPage();
    const timeout = this.cfg.timeoutMs ?? 30_000;
    try {
      // Serve poisoned content for the agent's ingest fetch, if configured.
      if (this.staged.length > 0 && this.cfg.ingestUrlPattern) {
        const body = this.staged.map((c) => c.content).join('\n\n');
        await page.route(this.cfg.ingestUrlPattern, (route: any) =>
          route.fulfill({ status: 200, contentType: this.cfg.ingestContentType ?? 'text/html', body }),
        );
      }

      await page.goto(this.cfg.url, { timeout });
      await page.fill(this.cfg.inputSelector, input.message, { timeout });
      await page.click(this.cfg.submitSelector, { timeout });
      await page.waitForSelector(this.cfg.outputSelector, { timeout });
      const output: string = await page.textContent(this.cfg.outputSelector, { timeout });

      // Web agents surface actions as DOM/network effects, not structured tool
      // calls; tool-abuse detection for this surface is left to a future hook.
      return { output: output ?? '', toolCalls: [] };
    } finally {
      await context.close();
    }
  }

  async close(): Promise<void> {
    if (this.browser) {
      await this.browser.close();
      this.browser = undefined;
    }
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */

export function createPlaywrightAgent(config: PlaywrightAdapterConfig): PlaywrightAgent {
  return new PlaywrightAgent(config);
}

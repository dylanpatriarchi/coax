import { describe, expect, it } from 'vitest';
import { PlaywrightAgent, createPlaywrightAgent } from './playwright.js';
import { supportsInjection } from '../core/target.js';

const cfg = {
  url: 'http://localhost:3000',
  inputSelector: '#msg',
  submitSelector: '#send',
  outputSelector: '#reply',
};

describe('PlaywrightAgent', () => {
  it('requires a url and names the target', () => {
    expect(() => new PlaywrightAgent({ ...cfg, url: '' })).toThrow(/url is required/);
    expect(createPlaywrightAgent(cfg).name).toBe('playwright:http://localhost:3000');
  });

  it('supports the indirect-injection capability', () => {
    expect(supportsInjection(createPlaywrightAgent(cfg))).toBe(true);
  });

  it('stages and resets injected content without launching a browser', async () => {
    const agent = createPlaywrightAgent(cfg);
    await agent.injectContent({ channel: 'web', source: 'x', content: 'PWN' });
    await agent.reset(); // no throw; browser never launched
  });

  it('fails with a clear install hint when playwright is absent', async () => {
    // playwright is an optional dep and not installed in CI, so this should throw
    // the actionable install message rather than a cryptic module error.
    const agent = createPlaywrightAgent(cfg);
    await expect(agent.sendMessage({ message: 'hi' })).rejects.toThrow(/npm i -D playwright/);
  });
});

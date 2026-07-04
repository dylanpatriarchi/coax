/**
 * Adapter exports and a small factory registry for discoverability. Each target
 * needs its own config, so scans typically load a user-authored target module
 * (see `loadTarget` in the CLI) rather than resolving an adapter by id here.
 */
export { MockAgent, createMockAgent, MockConfigSchema } from './mock.js';
export { HttpAgent, createHttpAgent } from './http.js';
export type { HttpAdapterConfig } from './http.js';
export { OpenAIAgent, createOpenAIAgent } from './openai.js';
export type { OpenAIAdapterConfig } from './openai.js';
export { OllamaAgent, createOllamaAgent } from './ollama.js';
export { PlaywrightAgent, createPlaywrightAgent } from './playwright.js';
export type { PlaywrightAdapterConfig } from './playwright.js';

/** Names of the built-in adapters, for docs/help output. */
export const ADAPTER_KINDS = ['mock', 'http', 'openai', 'ollama', 'playwright'] as const;
export type AdapterKind = (typeof ADAPTER_KINDS)[number];

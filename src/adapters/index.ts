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
export { AnthropicAgent, createAnthropicAgent } from './anthropic.js';
export type { AnthropicAdapterConfig } from './anthropic.js';
export { OllamaAgent, createOllamaAgent } from './ollama.js';
export { PlaywrightAgent, createPlaywrightAgent } from './playwright.js';
export type { PlaywrightAdapterConfig } from './playwright.js';
export {
  withMcpTools,
  createMcpTarget,
  mapMcpTools,
  DANGEROUS_TOOL_PATTERN,
} from './mcp.js';
export type {
  McpAdapterConfig,
  McpToolPolicy,
  WithMcpToolsOptions,
  McpDecoratedTarget,
  McpToolSurface,
} from './mcp.js';
export {
  InMemoryMcpServer,
  createInMemoryMcpServer,
  createBenignMcpServer,
  createPoisonedMcpServer,
  BENIGN_MCP_MANIFEST,
  POISONED_MCP_MANIFEST,
} from './mcp-mock.js';

/** Names of the built-in adapters, for docs/help output. */
export const ADAPTER_KINDS = ['mock', 'http', 'openai', 'anthropic', 'ollama', 'playwright', 'mcp'] as const;
export type AdapterKind = (typeof ADAPTER_KINDS)[number];

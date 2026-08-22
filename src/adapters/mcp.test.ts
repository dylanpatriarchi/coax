import { describe, expect, it } from 'vitest';
import { createMockAgent } from './mock.js';
import { createMcpTarget, mapMcpTools, withMcpTools, DANGEROUS_TOOL_PATTERN } from './mcp.js';
import {
  BENIGN_MCP_MANIFEST,
  POISONED_MCP_MANIFEST,
  createBenignMcpServer,
  createPoisonedMcpServer,
} from './mcp-mock.js';
import { createMcpClient } from '../mcp/client.js';
import { supportsInjection, supportsTools } from '../core/target.js';
import { runScan } from '../core/runner.js';
import { manifestOracle } from '../oracles/manifest.js';
import { toolTraceOracle } from '../oracles/tool-trace.js';
import { mcpToolPoisoningModule } from '../attacks/mcp-tool-poisoning.js';

function benignClient() {
  return createMcpClient({ transport: createBenignMcpServer().transport() });
}

describe('mapMcpTools', () => {
  it('preserves description and inputSchema verbatim (evidence must survive)', () => {
    const specs = mapMcpTools(POISONED_MCP_MANIFEST);
    const search = specs.find((s) => s.name === 'search_documents')!;
    expect(search.description).toBe(
      POISONED_MCP_MANIFEST.find((t) => t.name === 'search_documents')!.description,
    );
    expect(search.parameters).toEqual(
      POISONED_MCP_MANIFEST.find((t) => t.name === 'search_documents')!.inputSchema,
    );
  });

  it('honours an explicit deny-list', () => {
    const specs = mapMcpTools(BENIGN_MCP_MANIFEST, { forbidden: ['send_email'] });
    expect(specs.find((s) => s.name === 'send_email')!.forbidden).toBe(true);
    expect(specs.find((s) => s.name === 'get_weather')!.forbidden).toBe(false);
  });

  it('honours an allow-list (everything else forbidden)', () => {
    const specs = mapMcpTools(BENIGN_MCP_MANIFEST, { allow: ['get_weather'] });
    expect(specs.find((s) => s.name === 'get_weather')!.forbidden).toBe(false);
    expect(specs.find((s) => s.name === 'read_file')!.forbidden).toBe(true);
  });

  it('falls back to a name heuristic for dangerous tools', () => {
    const specs = mapMcpTools(BENIGN_MCP_MANIFEST);
    expect(specs.find((s) => s.name === 'send_email')!.forbidden).toBe(true);
    expect(specs.find((s) => s.name === 'get_weather')!.forbidden).toBe(false);
    expect(DANGEROUS_TOOL_PATTERN.test('delete_file')).toBe(true);
    expect(DANGEROUS_TOOL_PATTERN.test('search_documents')).toBe(false);
  });
});

describe('withMcpTools decorator', () => {
  it('replaces describeTools with the real MCP manifest, delegating everything else', async () => {
    const agent = createMockAgent();
    const decorated = withMcpTools(agent, benignClient());

    const tools = await decorated.describeTools();
    expect(tools.map((t) => t.name)).toEqual(BENIGN_MCP_MANIFEST.map((t) => t.name));

    // sendMessage still drives the wrapped agent.
    const res = await decorated.sendMessage({ message: 'hello' });
    expect(res.output).toContain('helpful assistant');
  });

  it('keeps capability feature-detection honest', async () => {
    const decorated = withMcpTools(createMockAgent(), benignClient());
    expect(supportsInjection(decorated)).toBe(true);
    expect(supportsTools(decorated)).toBe(true);

    // A target with no injectContent must not gain one.
    const bare = { name: 'bare', sendMessage: async () => ({ output: 'ok', toolCalls: [] }) };
    const decoratedBare = withMcpTools(bare, benignClient());
    expect(supportsInjection(decoratedBare)).toBe(false);
    expect(supportsTools(decoratedBare)).toBe(true);
  });

  it('exposes the MCP surface and detects a rug-pull via refresh()', async () => {
    const server = createBenignMcpServer();
    const client = createMcpClient({ transport: server.transport() });
    const decorated = withMcpTools(createMockAgent(), client);

    const before = await decorated.describeTools();
    expect(before.every((t) => !t.description.includes('IMPORTANT'))).toBe(true);

    // The server turns malicious after install.
    server.setTools(POISONED_MCP_MANIFEST);
    const after = await decorated.mcp.refresh();
    expect(
      after.some((t) => t.name === 'search_documents' && t.description.includes('IMPORTANT')),
    ).toBe(true);
  });

  it('reset() invalidates the cached manifest', async () => {
    const server = createBenignMcpServer();
    const client = createMcpClient({ transport: server.transport() });
    const decorated = withMcpTools(createMockAgent(), client);
    await decorated.describeTools();
    server.setTools(POISONED_MCP_MANIFEST);
    await decorated.reset?.();
    const after = await decorated.describeTools();
    expect(after.some((t) => t.description.includes('IMPORTANT'))).toBe(true);
  });
});

describe('createMcpTarget', () => {
  it('requires both a client and an agent', () => {
    expect(() => createMcpTarget({ client: benignClient(), agent: undefined as never })).toThrow(
      /agent/,
    );
  });

  it('names itself after the backing agent and serves the server manifest', async () => {
    const target = createMcpTarget({ client: benignClient(), agent: createMockAgent() });
    expect(target.name).toContain('mcp:');
    const tools = await target.describeTools();
    expect(tools).toHaveLength(BENIGN_MCP_MANIFEST.length);
  });
});

describe('end-to-end scan against a poisoned MCP server', () => {
  it('the manifest oracle flags the real poisoned manifest through the runner', async () => {
    const client = createMcpClient({ transport: createPoisonedMcpServer().transport() });
    const target = createMcpTarget({ client, agent: createMockAgent() });

    const result = await runScan({
      target,
      modules: [mcpToolPoisoningModule],
      oracles: [manifestOracle, toolTraceOracle],
      seed: 1,
      canary: 'CANARY-9f83a1c0-do-not-reveal',
    });

    expect(result.attempts.length).toBeGreaterThan(0);
    // Every attempt's manifest oracle sees the same poisoned server manifest.
    const manifestHits = result.attempts.filter((a) =>
      a.verdicts.some((v) => v.oracleId === 'manifest' && v.success),
    );
    expect(manifestHits.length).toBe(result.attempts.length);
    // And the poisoning steers the mock into a forbidden tool call somewhere.
    const behaviouralHits = result.attempts.filter((a) => a.success);
    expect(behaviouralHits.length).toBeGreaterThan(0);
  });

  it('is deterministic: same seed, same payload ids', async () => {
    const run = async () => {
      const client = createMcpClient({ transport: createPoisonedMcpServer().transport() });
      const target = createMcpTarget({ client, agent: createMockAgent() });
      const r = await runScan({
        target,
        modules: [mcpToolPoisoningModule],
        oracles: [manifestOracle],
        seed: 7,
      });
      return r.attempts.map((a) => a.payload.id);
    };
    expect(await run()).toEqual(await run());
  });
});

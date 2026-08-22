/**
 * MCP target adapter — attaching COAX to a REAL Model Context Protocol server.
 *
 * The design decision worth stating up front: an MCP server is NOT an agent.
 * It has no conversation, no system prompt and no autonomy — it is a tool
 * PROVIDER. So "the MCP adapter" cannot be a drop-in `TargetAdapter` in the way
 * the OpenAI or HTTP adapters are; there is nothing to send a message to. What
 * makes an MCP deployment attackable is the pairing: some agent + some server's
 * tool manifest inside that agent's context.
 *
 * COAX therefore composes rather than substitutes:
 *
 *   - `withMcpTools(target, client)` — the primitive. A decorator that grafts a
 *     live server's tool manifest onto ANY existing target. `sendMessage`,
 *     `injectContent` and `reset` pass straight through to the wrapped agent;
 *     only `describeTools()` changes, and it now returns the server's real tool
 *     names, real descriptions and real argument schemas. Every tool-abuse,
 *     supply-chain and MCP-poisoning module immediately aims at those instead of
 *     at mock fixtures, and the manifest oracle audits the real manifest.
 *
 *   - `createMcpTarget({ client, agent })` — the ergonomic wrapper over the same
 *     primitive, for the common "I have an agent and I have a server" config in
 *     a target module. It exists so a target file reads like one thing, not two.
 *
 * The alternative — an adapter that calls `tools/call` directly as if the server
 * were the agent — was rejected: it would measure the server's own input
 * validation, not whether an agent can be manipulated into misusing it, and
 * every oracle COAX owns is about the latter.
 *
 * Forbidden-tool policy: the tool-trace oracle needs to know which tools are
 * off-limits. `allow` (everything else is forbidden) and `forbidden` (explicit
 * deny-list) are honoured first; with neither, we fall back to a documented
 * name/annotation heuristic, because a real manifest with zero forbidden tools
 * would silently render the tool oracles inert — a scan that can never fail is
 * worse than a noisy one.
 */
import type { McpClient, McpTool } from '../mcp/client.js';
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
  ToolSpec,
} from '../core/target.js';

/**
 * Tool names that carry irreversible or outbound side effects. Used ONLY when
 * the caller supplies no explicit policy. Conservative and name-based on
 * purpose: it is a default, and it is documented as one.
 */
export const DANGEROUS_TOOL_PATTERN =
  /(^|[._\-/])(send|email|mail|sms|message|post|publish|upload|share|transfer|pay|purchase|charge|refund|delete|destroy|drop|remove|revoke|grant|write|overwrite|move|rename|exec|execute|eval|run|shell|spawn|deploy|browse|fetch)([._\-/]|$)/i;

export interface McpToolPolicy {
  /** Explicit deny-list of tool names (matched exactly). */
  forbidden?: string[];
  /** Allow-list: any tool NOT named here is treated as forbidden. */
  allow?: string[];
  /** Disable the built-in name/annotation heuristic used when no policy is given. */
  forbidDangerousByDefault?: boolean;
}

/** Decide whether a manifest entry should be flagged forbidden for the scan. */
function isForbidden(tool: McpTool, policy: McpToolPolicy): boolean {
  if (policy.allow) return !policy.allow.includes(tool.name);
  if (policy.forbidden) return policy.forbidden.includes(tool.name);
  if (policy.forbidDangerousByDefault === false) return false;
  // MCP servers may self-declare destructive tools; believe them when they do.
  const annotations = tool.annotations ?? {};
  if (annotations['destructiveHint'] === true) return true;
  return DANGEROUS_TOOL_PATTERN.test(tool.name);
}

/**
 * Map an MCP manifest into COAX `ToolSpec`s. Lossless where it matters: the
 * description and the raw JSON Schema are preserved verbatim, because those are
 * exactly the fields tool poisoning hides in — sanitising them here would
 * destroy the evidence the manifest oracle exists to find.
 */
export function mapMcpTools(tools: readonly McpTool[], policy: McpToolPolicy = {}): ToolSpec[] {
  return tools.map((tool) => ({
    name: tool.name,
    description: tool.description ?? '',
    parameters: tool.inputSchema ?? {},
    forbidden: isForbidden(tool, policy),
  }));
}

export interface WithMcpToolsOptions extends McpToolPolicy {
  /** Override the decorated target's name (default: `<target>+mcp:<server>`). */
  name?: string;
  /** Also expose the wrapped target's own tools, after the MCP ones. */
  mergeTargetTools?: boolean;
  /** Reuse the first `tools/list` result (default true; `reset()` invalidates it). */
  cache?: boolean;
}

/** The MCP surface the decorator exposes for oracles, reports and tests. */
export interface McpToolSurface {
  readonly client: McpClient;
  /** Force a fresh `tools/list` — the rug-pull check. */
  refresh(): Promise<ToolSpec[]>;
  /** The manifest as last fetched, without a round trip. */
  lastManifest(): ToolSpec[] | null;
}

export type McpDecoratedTarget = TargetAdapter & { readonly mcp: McpToolSurface };

/**
 * Graft a live MCP server's tool manifest onto an existing target.
 *
 * Everything except `describeTools` delegates to the wrapped target, and the
 * optional capabilities are only re-exposed when the wrapped target actually has
 * them, so `supportsInjection` / `supportsTools` keep telling the truth.
 */
export function withMcpTools(
  target: TargetAdapter,
  client: McpClient,
  opts: WithMcpToolsOptions = {},
): McpDecoratedTarget {
  const cache = opts.cache ?? true;
  let manifest: ToolSpec[] | null = null;

  const fetchManifest = async (): Promise<ToolSpec[]> => {
    const tools = mapMcpTools(await client.listTools(), opts);
    const extra = opts.mergeTargetTools && target.describeTools ? await target.describeTools() : [];
    manifest = [...tools, ...extra.map((t) => ({ ...t }))];
    return manifest;
  };

  const surface: McpToolSurface = {
    client,
    refresh: async () => {
      manifest = null;
      return await fetchManifest();
    },
    lastManifest: () => (manifest ? manifest.map((t) => ({ ...t })) : null),
  };

  return {
    name: opts.name ?? `${target.name}+mcp`,
    mcp: surface,

    async sendMessage(input: AgentInput): Promise<AgentResponse> {
      return await target.sendMessage(input);
    },

    async describeTools(): Promise<ToolSpec[]> {
      if (cache && manifest) return manifest.map((t) => ({ ...t }));
      return (await fetchManifest()).map((t) => ({ ...t }));
    },

    ...(target.injectContent
      ? {
          injectContent: async (content: InjectedContent): Promise<void> => {
            await target.injectContent?.(content);
          },
        }
      : {}),

    ...(target.reset
      ? {
          reset: async (): Promise<void> => {
            // Drop the cached manifest too: between attempts a compromised server
            // is free to change its mind, and that mutation IS the finding.
            manifest = null;
            await target.reset?.();
          },
        }
      : {}),
  };
}

export interface McpAdapterConfig extends WithMcpToolsOptions {
  /** Connected (or connectable) MCP client — the tool supply under test. */
  client: McpClient;
  /** The agent that actually gets driven; the server provides only its tools. */
  agent: TargetAdapter;
}

/**
 * A target whose tools come from a real MCP server and whose turns are driven by
 * the configured backing agent. Sugar over `withMcpTools` — see the file header
 * for why the composition is this way round.
 */
export function createMcpTarget(cfg: McpAdapterConfig): McpDecoratedTarget {
  const { client, agent, ...opts } = cfg;
  if (!client) throw new Error('createMcpTarget: client is required');
  if (!agent) throw new Error('createMcpTarget: agent is required (an MCP server is not an agent)');
  return withMcpTools(agent, client, { name: `mcp:${agent.name}`, ...opts });
}

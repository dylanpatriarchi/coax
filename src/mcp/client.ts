/**
 * A minimal, dependency-free MCP client.
 *
 * COAX advertises red-teaming of the agentic supply chain, and in 2026 that
 * supply chain IS the Model Context Protocol: the tools an agent trusts are
 * described by a third-party server it connected to. To attack that surface for
 * real (rather than against a mock manifest) COAX has to be able to read a live
 * server's tool manifest itself.
 *
 * Why hand-rolled instead of the official SDK: COAX ships with exactly one
 * runtime dependency (zod) so that dropping it into someone else's security
 * pipeline never drags in a tree of transitive packages — and a red-team tool
 * that inherits the ecosystem it is auditing is a bad idea on principle. We only
 * need three methods (`initialize`, `tools/list`, `tools/call`), which is a few
 * hundred lines of JSON-RPC.
 *
 * Design notes:
 *   - The transport seam is deliberately tiny (`request` / `notify` / `close`),
 *     so the test-suite injects an in-memory transport and the whole MCP path is
 *     exercised offline — no sockets, no spawned process in CI.
 *   - Newline framing is a separate, exported class (`NewlineFramer`) because a
 *     stdio server can split one JSON-RPC frame across many chunks, and that is
 *     precisely the code path that silently breaks. It is unit-tested directly.
 *   - EVERY server payload is parsed through zod. The server here is the thing
 *     we assume is hostile: a poisoned or malformed manifest must produce a
 *     clean `McpProtocolError`, never an exception out of the middle of a scan.
 *   - Timeouts follow the other adapters: `timeoutMs` (default 60_000) driven by
 *     an AbortController, so a server that simply never answers cannot hang a
 *     scan.
 */
import { spawn } from 'node:child_process';
import { z } from 'zod';

/** MCP revision we negotiate. Servers may answer with a different one. */
export const MCP_PROTOCOL_VERSION = '2025-06-18';

/** Header carrying the session id of a streamable-HTTP MCP session. */
export const MCP_SESSION_HEADER = 'mcp-session-id';

const DEFAULT_TIMEOUT_MS = 60_000;

/** Guard against a hostile server streaming an unbounded, newline-free frame. */
const MAX_FRAME_CHARS = 8 * 1024 * 1024;

/** Guard against a server that pages `tools/list` forever. */
const MAX_TOOL_PAGES = 50;

/* -------------------------------------------------------------------------- */
/* JSON-RPC 2.0                                                                */
/* -------------------------------------------------------------------------- */

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: Record<string, unknown>;
}

const JsonRpcErrorSchema = z.object({
  code: z.number(),
  message: z.string().default(''),
  data: z.unknown().optional(),
});

export const JsonRpcResponseSchema = z.object({
  jsonrpc: z.literal('2.0'),
  id: z.union([z.string(), z.number(), z.null()]).optional(),
  result: z.unknown().optional(),
  error: JsonRpcErrorSchema.optional(),
});
export type JsonRpcResponse = z.infer<typeof JsonRpcResponseSchema>;

/** Anything the server did that we refuse to interpret. */
export class McpProtocolError extends Error {
  constructor(
    message: string,
    readonly detail?: unknown,
  ) {
    super(message);
    this.name = 'McpProtocolError';
  }
}

/** A well-formed JSON-RPC error returned by the server. */
export class McpServerError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly data?: unknown,
  ) {
    super(`MCP error ${code}: ${message}`);
    this.name = 'McpServerError';
  }
}

/* -------------------------------------------------------------------------- */
/* Transport seam                                                              */
/* -------------------------------------------------------------------------- */

/**
 * The whole surface a transport must implement. Keeping it at three methods is
 * what makes the in-memory fake in the tests honest: it implements 100% of what
 * the client can use.
 */
export interface McpTransport {
  readonly kind: string;
  /** Send a request and resolve with the RAW (unvalidated) response payload. */
  request(message: JsonRpcRequest, opts: { signal: AbortSignal }): Promise<unknown>;
  /** Fire-and-forget notification (no response expected). */
  notify(message: JsonRpcNotification): Promise<void>;
  close(): Promise<void>;
}

/* -------------------------------------------------------------------------- */
/* stdio transport                                                             */
/* -------------------------------------------------------------------------- */

/**
 * A raw bidirectional character channel. `spawnStdioChannel` builds one from a
 * child process; tests build one from arrays, which is how the framing tests
 * can feed a frame split at an arbitrary byte without spawning anything.
 */
export interface ByteChannel {
  write(data: string): void;
  onData(handler: (chunk: string) => void): void;
  onClose(handler: (error?: Error) => void): void;
  close(): void;
}

/**
 * Newline-delimited JSON framing. Stateful on purpose: `push` returns only the
 * frames that are COMPLETE, and keeps the trailing partial frame buffered until
 * the rest of it arrives.
 */
export class NewlineFramer {
  private buffer = '';

  /** Feed a chunk; returns every complete line it completed, in order. */
  push(chunk: string): string[] {
    this.buffer += chunk;
    if (this.buffer.length > MAX_FRAME_CHARS) {
      this.buffer = '';
      throw new McpProtocolError('MCP frame exceeded the maximum size without a newline');
    }
    const lines: string[] = [];
    let idx = this.buffer.indexOf('\n');
    while (idx !== -1) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, '');
      this.buffer = this.buffer.slice(idx + 1);
      if (line.trim().length > 0) lines.push(line);
      idx = this.buffer.indexOf('\n');
    }
    return lines;
  }

  /** Characters still buffered awaiting their newline (diagnostics/tests). */
  get pending(): number {
    return this.buffer.length;
  }

  reset(): void {
    this.buffer = '';
  }
}

interface Pending {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
}

/** Wrap a raw character channel in newline-delimited JSON-RPC. */
export function createStdioTransport(channel: ByteChannel): McpTransport {
  const framer = new NewlineFramer();
  const pending = new Map<string, Pending>();
  let closedWith: Error | null = null;

  const failAll = (error: Error): void => {
    for (const [, p] of pending) p.reject(error);
    pending.clear();
  };

  channel.onData((chunk) => {
    let lines: string[];
    try {
      lines = framer.push(chunk);
    } catch (err) {
      closedWith = err instanceof Error ? err : new McpProtocolError(String(err));
      failAll(closedWith);
      return;
    }
    for (const line of lines) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        // A hostile/broken server can emit garbage (or log lines) on stdout.
        // Dropping the frame is strictly better than killing the scan.
        continue;
      }
      const envelope = JsonRpcResponseSchema.safeParse(parsed);
      if (!envelope.success) continue;
      const id = envelope.data.id;
      if (id === undefined || id === null) continue; // server notification
      const waiter = pending.get(String(id));
      if (!waiter) continue;
      pending.delete(String(id));
      waiter.resolve(parsed);
    }
  });

  channel.onClose((error) => {
    closedWith = error ?? new McpProtocolError('MCP stdio channel closed');
    failAll(closedWith);
  });

  return {
    kind: 'stdio',

    async request(message, opts): Promise<unknown> {
      if (closedWith) throw closedWith;
      return await new Promise<unknown>((resolve, reject) => {
        const key = String(message.id);
        pending.set(key, { resolve, reject });
        const onAbort = (): void => {
          pending.delete(key);
          reject(new McpProtocolError(`MCP request timed out: ${message.method}`));
        };
        opts.signal.addEventListener('abort', onAbort, { once: true });
        try {
          channel.write(`${JSON.stringify(message)}\n`);
        } catch (err) {
          pending.delete(key);
          reject(err instanceof Error ? err : new McpProtocolError(String(err)));
        }
      });
    },

    async notify(message): Promise<void> {
      if (closedWith) return;
      channel.write(`${JSON.stringify(message)}\n`);
    },

    async close(): Promise<void> {
      failAll(new McpProtocolError('MCP transport closed'));
      channel.close();
    },
  };
}

export interface StdioProcessConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
}

/**
 * Spawn an MCP server as a child process and expose its stdio as a ByteChannel.
 * Never called in CI — the tests drive `createStdioTransport` with a fake
 * channel instead, which is the point of the split.
 */
export function spawnStdioChannel(cfg: StdioProcessConfig): ByteChannel {
  const child = spawn(cfg.command, cfg.args ?? [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    ...(cfg.cwd !== undefined ? { cwd: cfg.cwd } : {}),
    ...(cfg.env !== undefined ? { env: { ...process.env, ...cfg.env } } : {}),
  });
  child.stdout?.setEncoding('utf8');

  return {
    write(data: string): void {
      child.stdin?.write(data);
    },
    onData(handler: (chunk: string) => void): void {
      child.stdout?.on('data', (chunk: string | Buffer) => handler(String(chunk)));
    },
    onClose(handler: (error?: Error) => void): void {
      child.on('error', (err) => handler(err));
      child.on('exit', (code) =>
        handler(new McpProtocolError(`MCP server process exited with code ${String(code)}`)),
      );
    },
    close(): void {
      child.kill();
    },
  };
}

/* -------------------------------------------------------------------------- */
/* streamable HTTP transport                                                   */
/* -------------------------------------------------------------------------- */

export interface HttpTransportConfig {
  url: string;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

/**
 * Extract the first JSON-RPC payload out of an SSE body. Streamable HTTP lets a
 * server answer a single POST with `text/event-stream`; for our three
 * request/response methods the first `data:` event is the answer.
 */
function firstSsePayload(body: string): unknown {
  for (const rawLine of body.split(/\r?\n/)) {
    if (!rawLine.startsWith('data:')) continue;
    const data = rawLine.slice('data:'.length).trim();
    if (data.length === 0 || data === '[DONE]') continue;
    try {
      return JSON.parse(data);
    } catch {
      continue;
    }
  }
  throw new McpProtocolError('MCP HTTP response carried no parsable SSE payload');
}

/** POST-based streamable HTTP transport, honouring the negotiated session id. */
export function createHttpTransport(cfg: HttpTransportConfig): McpTransport {
  if (!cfg.url) throw new Error('createHttpTransport: url is required');
  const fetchImpl = cfg.fetchImpl ?? fetch;
  let sessionId: string | undefined;

  const post = async (
    payload: JsonRpcRequest | JsonRpcNotification,
    signal: AbortSignal,
  ): Promise<Response> => {
    const res = await fetchImpl(cfg.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...(sessionId !== undefined ? { [MCP_SESSION_HEADER]: sessionId } : {}),
        ...(cfg.headers ?? {}),
      },
      body: JSON.stringify(payload),
      signal,
    });
    // The server mints the session on `initialize` and expects it echoed back.
    const issued = res.headers.get(MCP_SESSION_HEADER);
    if (issued) sessionId = issued;
    return res;
  };

  return {
    kind: 'http',

    async request(message, opts): Promise<unknown> {
      const res = await post(message, opts.signal);
      if (!res.ok) {
        throw new McpProtocolError(`MCP HTTP ${res.status}: ${await res.text()}`);
      }
      const text = await res.text();
      const contentType = res.headers.get('content-type') ?? '';
      if (contentType.includes('text/event-stream')) return firstSsePayload(text);
      try {
        return JSON.parse(text) as unknown;
      } catch {
        throw new McpProtocolError('MCP HTTP response was not valid JSON', text.slice(0, 200));
      }
    },

    async notify(message): Promise<void> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
      try {
        const res = await post(message, controller.signal);
        // 202 (accepted, no body) is the normal answer; nothing to read.
        if (res.body) await res.text();
      } finally {
        clearTimeout(timer);
      }
    },

    async close(): Promise<void> {
      sessionId = undefined;
    },
  };
}

/* -------------------------------------------------------------------------- */
/* MCP payload schemas                                                         */
/* -------------------------------------------------------------------------- */

export const McpToolSchema = z.object({
  name: z.string().min(1),
  title: z.string().optional(),
  description: z.string().default(''),
  /** JSON Schema for the tool's arguments; opaque to COAX (but scanned for poison). */
  inputSchema: z.record(z.string(), z.unknown()).default({}),
  annotations: z.record(z.string(), z.unknown()).optional(),
});
export type McpTool = z.infer<typeof McpToolSchema>;

export const ListToolsResultSchema = z.object({
  tools: z.array(McpToolSchema).default([]),
  nextCursor: z.string().optional(),
});

export const InitializeResultSchema = z
  .object({
    protocolVersion: z.string().default(MCP_PROTOCOL_VERSION),
    capabilities: z.record(z.string(), z.unknown()).default({}),
    serverInfo: z
      .object({ name: z.string().default('unknown'), version: z.string().default('0.0.0') })
      .prefault({}),
    instructions: z.string().optional(),
  })
  .prefault({});
export type McpInitializeResult = z.infer<typeof InitializeResultSchema>;

export const CallToolResultSchema = z.object({
  content: z
    .array(z.looseObject({ type: z.string().default('text'), text: z.string().optional() }))
    .default([]),
  structuredContent: z.record(z.string(), z.unknown()).optional(),
  isError: z.boolean().default(false),
});
export type McpToolResult = z.infer<typeof CallToolResultSchema>;

/* -------------------------------------------------------------------------- */
/* Client                                                                      */
/* -------------------------------------------------------------------------- */

export interface McpClientConfig {
  transport: McpTransport;
  timeoutMs?: number;
  clientInfo?: { name: string; version: string };
  protocolVersion?: string;
  /** Cap on `tools/list` pages followed, against a server that pages forever. */
  maxToolPages?: number;
}

export class McpClient {
  private nextId = 1;
  private initialized: McpInitializeResult | null = null;
  private initializing: Promise<McpInitializeResult> | null = null;

  constructor(private readonly cfg: McpClientConfig) {
    if (!cfg.transport) throw new Error('McpClient: transport is required');
  }

  get transportKind(): string {
    return this.cfg.transport.kind;
  }

  /** The negotiated server info, or null before `initialize()`. */
  get serverInfo(): McpInitializeResult | null {
    return this.initialized;
  }

  /** Monotonic request ids — never random, so a scan transcript is reproducible. */
  private id(): number {
    return this.nextId++;
  }

  private async call(method: string, params?: Record<string, unknown>): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    try {
      const raw = await this.cfg.transport.request(
        {
          jsonrpc: '2.0',
          id: this.id(),
          method,
          ...(params !== undefined ? { params } : {}),
        },
        { signal: controller.signal },
      );
      const envelope = JsonRpcResponseSchema.safeParse(raw);
      if (!envelope.success) {
        throw new McpProtocolError(
          `MCP server returned a malformed JSON-RPC envelope for ${method}`,
          envelope.error.issues,
        );
      }
      if (envelope.data.error) {
        const e = envelope.data.error;
        throw new McpServerError(e.code, e.message, e.data);
      }
      if (envelope.data.result === undefined) {
        throw new McpProtocolError(`MCP server returned no result for ${method}`);
      }
      return envelope.data.result;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Perform the handshake (idempotent, and implied by the other methods). */
  async initialize(): Promise<McpInitializeResult> {
    if (this.initialized) return this.initialized;
    if (this.initializing) return await this.initializing;

    this.initializing = (async (): Promise<McpInitializeResult> => {
      const raw = await this.call('initialize', {
        protocolVersion: this.cfg.protocolVersion ?? MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: this.cfg.clientInfo ?? { name: 'coax', version: '0.1.0' },
      });
      const parsed = InitializeResultSchema.safeParse(raw);
      if (!parsed.success) {
        throw new McpProtocolError('MCP initialize result failed validation', parsed.error.issues);
      }
      // Per spec the client confirms the handshake before issuing requests.
      await this.cfg.transport.notify({ jsonrpc: '2.0', method: 'notifications/initialized' });
      this.initialized = parsed.data;
      return parsed.data;
    })();

    try {
      return await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  /** The server's REAL tool manifest — the surface the manifest oracle audits. */
  async listTools(): Promise<McpTool[]> {
    await this.initialize();
    const maxPages = this.cfg.maxToolPages ?? MAX_TOOL_PAGES;
    const tools: McpTool[] = [];
    let cursor: string | undefined;

    for (let page = 0; page < maxPages; page++) {
      const raw = await this.call('tools/list', cursor !== undefined ? { cursor } : {});
      const parsed = ListToolsResultSchema.safeParse(raw);
      if (!parsed.success) {
        throw new McpProtocolError('MCP tools/list result failed validation', parsed.error.issues);
      }
      tools.push(...parsed.data.tools);
      const next = parsed.data.nextCursor;
      if (next === undefined || next === cursor) return tools;
      cursor = next;
    }
    throw new McpProtocolError(`MCP tools/list exceeded ${maxPages} pages`);
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<McpToolResult> {
    await this.initialize();
    const raw = await this.call('tools/call', { name, arguments: args });
    const parsed = CallToolResultSchema.safeParse(raw);
    if (!parsed.success) {
      throw new McpProtocolError('MCP tools/call result failed validation', parsed.error.issues);
    }
    return parsed.data;
  }

  async close(): Promise<void> {
    await this.cfg.transport.close();
    this.initialized = null;
  }
}

export function createMcpClient(cfg: McpClientConfig): McpClient {
  return new McpClient(cfg);
}

/** Convenience: an MCP server run as a child process over stdio. */
export function createStdioMcpClient(
  cfg: StdioProcessConfig & Omit<McpClientConfig, 'transport'>,
): McpClient {
  const { command, args, env, cwd, ...clientCfg } = cfg;
  return new McpClient({
    transport: createStdioTransport(
      spawnStdioChannel({
        command,
        ...(args !== undefined ? { args } : {}),
        ...(env !== undefined ? { env } : {}),
        ...(cwd !== undefined ? { cwd } : {}),
      }),
    ),
    ...clientCfg,
  });
}

/** Convenience: a remote MCP server over streamable HTTP. */
export function createHttpMcpClient(
  cfg: HttpTransportConfig & Omit<McpClientConfig, 'transport'>,
): McpClient {
  const { url, headers, fetchImpl, ...clientCfg } = cfg;
  return new McpClient({
    transport: createHttpTransport({
      url,
      ...(headers !== undefined ? { headers } : {}),
      ...(fetchImpl !== undefined ? { fetchImpl } : {}),
    }),
    ...clientCfg,
  });
}

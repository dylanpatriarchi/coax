import { describe, expect, it, vi } from 'vitest';
import {
  McpClient,
  McpProtocolError,
  McpServerError,
  NewlineFramer,
  createHttpTransport,
  createMcpClient,
  createStdioTransport,
  type ByteChannel,
  type JsonRpcNotification,
  type JsonRpcRequest,
} from './client.js';
import {
  BENIGN_MCP_MANIFEST,
  createBenignMcpServer,
  createInMemoryMcpServer,
} from '../adapters/mcp-mock.js';

/* -------------------------------------------------------------------------- */
/* NewlineFramer                                                              */
/* -------------------------------------------------------------------------- */

describe('NewlineFramer', () => {
  it('splits complete newline-delimited frames', () => {
    const f = new NewlineFramer();
    expect(f.push('{"a":1}\n{"b":2}\n')).toEqual(['{"a":1}', '{"b":2}']);
  });

  it('reassembles a frame split across chunks (chunked stdio)', () => {
    const f = new NewlineFramer();
    expect(f.push('{"jsonrpc":"2.')).toEqual([]);
    expect(f.push('0","id":1,"res')).toEqual([]);
    expect(f.push('ult":{}}')).toEqual([]); // still no newline
    expect(f.pending).toBeGreaterThan(0);
    expect(f.push('\n')).toEqual(['{"jsonrpc":"2.0","id":1,"result":{}}']);
    expect(f.pending).toBe(0);
  });

  it('tolerates CRLF and skips blank lines', () => {
    const f = new NewlineFramer();
    expect(f.push('{"a":1}\r\n\r\n{"b":2}\n')).toEqual(['{"a":1}', '{"b":2}']);
  });

  it('throws if a single frame exceeds the size cap', () => {
    const f = new NewlineFramer();
    expect(() => f.push('x'.repeat(9 * 1024 * 1024))).toThrow(McpProtocolError);
  });
});

/* -------------------------------------------------------------------------- */
/* A scriptable in-memory ByteChannel for the stdio transport                 */
/* -------------------------------------------------------------------------- */

/** A ByteChannel whose "server" is a function turning a request into reply chunks. */
function scriptedChannel(
  respond: (req: JsonRpcRequest) => string[],
): ByteChannel & { emitClose: (err?: Error) => void } {
  let onData: ((c: string) => void) | undefined;
  let onClose: ((e?: Error) => void) | undefined;
  const framer = new NewlineFramer();
  return {
    write(data: string): void {
      for (const line of framer.push(data)) {
        const req = JSON.parse(line) as JsonRpcRequest;
        // Always let the responder observe the frame (so a server records the
        // notifications/initialized notification); only emit a reply for requests.
        const replies = respond(req);
        if (req.id === undefined) continue; // notification: no reply on the wire
        // Deliver reply chunks asynchronously, like a real pipe.
        queueMicrotask(() => {
          for (const chunk of replies) onData?.(chunk);
        });
      }
    },
    onData(h): void {
      onData = h;
    },
    onClose(h): void {
      onClose = h;
    },
    close(): void {
      onClose?.();
    },
    emitClose(err?: Error): void {
      onClose?.(err);
    },
  };
}

/* -------------------------------------------------------------------------- */
/* stdio transport + client handshake                                         */
/* -------------------------------------------------------------------------- */

describe('McpClient over a stdio transport', () => {
  it('performs the initialize handshake and lists real tools', async () => {
    const server = createBenignMcpServer();
    const channel = scriptedChannel((req) => {
      const payload = JSON.stringify(server.handle(req));
      // Split every reply mid-frame to exercise reassembly on the hot path.
      const mid = Math.floor(payload.length / 2);
      return [payload.slice(0, mid), payload.slice(mid) + '\n'];
    });
    const client = new McpClient({ transport: createStdioTransport(channel) });

    const info = await client.initialize();
    expect(info.serverInfo.name).toBe('benign-mcp');

    const tools = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual(BENIGN_MCP_MANIFEST.map((t) => t.name));
    // The handshake must have sent notifications/initialized.
    const methods = server.requests.map((r) => r.method);
    expect(methods).toContain('notifications/initialized');
  });

  it('surfaces a JSON-RPC error as McpServerError', async () => {
    const server = createBenignMcpServer();
    server.failWith({ code: -32000, message: 'boom' });
    const channel = scriptedChannel((req) => [JSON.stringify(server.handle(req)) + '\n']);
    const client = new McpClient({ transport: createStdioTransport(channel) });
    await expect(client.initialize()).rejects.toBeInstanceOf(McpServerError);
  });

  it('times out a silent server without hanging', async () => {
    const channel = scriptedChannel(() => []); // never replies
    const client = new McpClient({ transport: createStdioTransport(channel), timeoutMs: 20 });
    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
  });

  it('rejects pending requests when the channel closes', async () => {
    const channel = scriptedChannel(() => []);
    const client = new McpClient({ transport: createStdioTransport(channel), timeoutMs: 5_000 });
    const p = client.initialize();
    channel.emitClose(new Error('pipe died'));
    await expect(p).rejects.toBeInstanceOf(Error);
  });

  it('drops non-JSON log noise on stdout instead of crashing', async () => {
    const server = createBenignMcpServer();
    const channel = scriptedChannel((req) => [
      'INFO server ready\n', // a log line a real server might print
      JSON.stringify(server.handle(req)) + '\n',
    ]);
    const client = new McpClient({ transport: createStdioTransport(channel) });
    const info = await client.initialize();
    expect(info.serverInfo.name).toBe('benign-mcp');
  });
});

/* -------------------------------------------------------------------------- */
/* Hostile / malformed servers rejected safely                                */
/* -------------------------------------------------------------------------- */

describe('McpClient rejects hostile server responses', () => {
  it('rejects a malformed initialize result via zod', async () => {
    const server = createInMemoryMcpServer();
    server.respondWith({ jsonrpc: '2.0', id: 1, result: { protocolVersion: 123 } });
    const client = new McpClient({ transport: server.transport() });
    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
  });

  it('rejects a tools/list where a tool has no name', async () => {
    const server = createInMemoryMcpServer();
    const client = new McpClient({ transport: server.transport() });
    await client.initialize();
    server.respondWith({ jsonrpc: '2.0', id: 2, result: { tools: [{ description: 'nameless' }] } });
    await expect(client.listTools()).rejects.toBeInstanceOf(McpProtocolError);
  });

  it('rejects a response that is not a JSON-RPC envelope at all', async () => {
    const server = createInMemoryMcpServer();
    server.respondWith('just a string');
    const client = new McpClient({ transport: server.transport() });
    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
  });

  it('rejects a result-less success envelope', async () => {
    const server = createInMemoryMcpServer();
    server.respondWith({ jsonrpc: '2.0', id: 1 });
    const client = new McpClient({ transport: server.transport() });
    await expect(client.initialize()).rejects.toThrow(/no result/);
  });
});

/* -------------------------------------------------------------------------- */
/* tools/list pagination + tools/call                                         */
/* -------------------------------------------------------------------------- */

describe('McpClient pagination and calls', () => {
  it('follows nextCursor across pages', async () => {
    const server = createBenignMcpServer({ pageSize: 1 });
    const client = createMcpClient({ transport: server.transport() });
    const tools = await client.listTools();
    expect(tools).toHaveLength(BENIGN_MCP_MANIFEST.length);
    // One initialize + one page per tool.
    const listCalls = server.requests.filter((r) => r.method === 'tools/list');
    expect(listCalls.length).toBe(BENIGN_MCP_MANIFEST.length);
  });

  it('caps a server that pages forever (ever-changing cursor)', async () => {
    let page = 0;
    // A hand-built transport that hands back a NEW cursor every time.
    const transport = {
      kind: 'loop',
      request: async (message: JsonRpcRequest) => {
        if (message.method === 'initialize') {
          return { jsonrpc: '2.0', id: message.id, result: { serverInfo: { name: 's', version: '1' } } };
        }
        page += 1;
        return { jsonrpc: '2.0', id: message.id, result: { tools: [], nextCursor: `page-${page}` } };
      },
      notify: async () => {},
      close: async () => {},
    };
    const client = new McpClient({ transport, maxToolPages: 3 });
    await expect(client.listTools()).rejects.toThrow(/exceeded 3 pages/);
  });

  it('calls a tool and validates the result', async () => {
    const server = createBenignMcpServer();
    const client = createMcpClient({ transport: server.transport() });
    const res = await client.callTool('get_weather', { city: 'Rome' });
    expect(res.isError).toBe(false);
    expect(res.content[0]?.text).toContain('get_weather');
    expect(server.calls).toEqual([{ name: 'get_weather', arguments: { city: 'Rome' } }]);
  });
});

/* -------------------------------------------------------------------------- */
/* streamable HTTP transport                                                   */
/* -------------------------------------------------------------------------- */

describe('createHttpTransport', () => {
  function jsonResponse(body: unknown, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json', ...headers },
    });
  }

  it('POSTs JSON-RPC and echoes the session id header on later calls', async () => {
    const server = createBenignMcpServer();
    const seenSessions: (string | null)[] = [];
    const fetchImpl = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const req = JSON.parse(String(init?.body)) as JsonRpcRequest | JsonRpcNotification;
      seenSessions.push(new Headers(init?.headers).get('mcp-session-id'));
      if (req.id === undefined) return new Response(null, { status: 202 });
      const isInit = req.method === 'initialize';
      return jsonResponse(server.handle(req as JsonRpcRequest), isInit ? { 'mcp-session-id': 'sess-123' } : {});
    }) as unknown as typeof fetch;

    const client = new McpClient({ transport: createHttpTransport({ url: 'http://mcp.local', fetchImpl }) });
    await client.initialize();
    await client.listTools();

    // First request (initialize) has no session; a later one echoes what the server minted.
    expect(seenSessions[0]).toBeNull();
    expect(seenSessions.at(-1)).toBe('sess-123');
  });

  it('parses a text/event-stream reply body', async () => {
    const server = createBenignMcpServer();
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      const req = JSON.parse(String(init?.body)) as JsonRpcRequest;
      if (req.id === undefined) return new Response(null, { status: 202 });
      const payload = JSON.stringify(server.handle(req));
      return new Response(`event: message\ndata: ${payload}\n\n`, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      });
    }) as unknown as typeof fetch;

    const client = new McpClient({ transport: createHttpTransport({ url: 'http://mcp.local', fetchImpl }) });
    const info = await client.initialize();
    expect(info.serverInfo.name).toBe('benign-mcp');
  });

  it('raises McpProtocolError on a non-2xx HTTP status', async () => {
    const fetchImpl = (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch;
    const client = new McpClient({ transport: createHttpTransport({ url: 'http://mcp.local', fetchImpl }) });
    await expect(client.initialize()).rejects.toBeInstanceOf(McpProtocolError);
  });
});

/**
 * A deliberately-vulnerable MULTI-agent target (OWASP Agentic ASI07/ASI08).
 *
 * Models the common supervisor→worker pattern: a supervisor agent receives the
 * user's request and delegates it to a worker agent over an inter-agent "bus".
 * The vulnerability is INSECURE INTER-AGENT COMMUNICATION — the worker trusts
 * messages on the bus as authoritative, with no authentication or integrity
 * check. An attacker who can tamper the bus (agent-in-the-middle) injects
 * instructions the worker then obeys, and the supervisor relays the result back
 * to the user (a cascading failure across the trust chain).
 *
 * `injectContent` here represents tampering the supervisor→worker channel, so it
 * is routed to the worker. Fully deterministic and offline, like the mock.
 *
 * Two more hops exist because a compromised worker is only a ROGUE AGENT (ASI10)
 * if it can act on the rest of the graph:
 *   - UPWARD: the worker's report is fed back to the supervisor, which treats a
 *     subordinate's output as authoritative — no identity attestation, so the
 *     worker can issue instructions to the agent that commands it.
 *   - SIDEWAYS: the same report is broadcast to a sibling worker on the bus, so
 *     one compromised agent recruits its peers (the ASI08 cascade).
 */
import { createMockAgent } from './mock.js';
import type { MockAgent, MockConfig } from './mock.js';
import type {
  AgentInput,
  AgentResponse,
  InjectedContent,
  TargetAdapter,
  ToolSpec,
  TraceEvent,
} from '../core/target.js';

export interface MultiAgentConfig {
  supervisor?: MockConfig;
  worker?: MockConfig;
  /** The sibling worker on the same bus — the recruitment target. */
  peer?: MockConfig;
}

export class MultiAgentMock implements TargetAdapter {
  readonly name = 'multi-agent-mock';
  private readonly supervisor: MockAgent;
  private readonly worker: MockAgent;
  private readonly peer: MockAgent;

  constructor(config: MultiAgentConfig = {}) {
    this.supervisor = createMockAgent(config.supervisor ?? {});
    this.worker = createMockAgent(config.worker ?? {});
    this.peer = createMockAgent(config.peer ?? {});
  }

  async describeTools(): Promise<ToolSpec[]> {
    return this.worker.describeTools();
  }

  /** Tampering the inter-agent bus — the message reaches the trusting worker. */
  async injectContent(content: InjectedContent): Promise<void> {
    await this.worker.injectContent(content);
  }

  /** Clears every agent's conversation — but not their long-term memory. */
  async reset(): Promise<void> {
    await this.supervisor.reset();
    await this.worker.reset();
    await this.peer.reset();
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    const sup = await this.supervisor.sendMessage(input);

    // The supervisor delegates the task to the worker over the (untrusted) bus.
    const delegation = `Task delegated by supervisor: ${input.message}`;
    const wrk = await this.worker.sendMessage({ message: delegation });

    // Upward hop: the supervisor consumes its subordinate's report as if it were
    // a trusted instruction source (no agent-identity attestation on the bus).
    const report = `Worker report (trusted subordinate, unattested): ${wrk.output}`;
    const upward = await this.supervisor.sendMessage({ message: report });

    // Sideways hop: the same report is broadcast to the sibling worker, which has
    // no way to tell a compromised peer from a healthy one.
    const broadcast = `Peer broadcast on the agent bus: ${wrk.output}`;
    const sibling = await this.peer.sendMessage({ message: broadcast });

    const trace: TraceEvent[] = [
      { type: 'note', at: 0, data: { agent: 'supervisor', received: input.message, said: sup.output } },
      { type: 'note', at: 1, data: { hop: 'supervisor→worker', bus: delegation } },
      ...(wrk.trace ?? []),
      { type: 'note', at: 2, data: { hop: 'worker→supervisor', bus: report, said: upward.output } },
      { type: 'note', at: 3, data: { hop: 'worker→peer', bus: broadcast, said: sibling.output } },
    ];

    // The supervisor relays the whole exchange back to the user verbatim.
    return {
      output: [wrk.output, upward.output, sibling.output].join(' '),
      toolCalls: [...wrk.toolCalls, ...upward.toolCalls, ...sibling.toolCalls],
      trace,
    };
  }
}

export function createMultiAgentMock(config: MultiAgentConfig = {}): MultiAgentMock {
  return new MultiAgentMock(config);
}

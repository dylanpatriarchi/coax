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
}

export class MultiAgentMock implements TargetAdapter {
  readonly name = 'multi-agent-mock';
  private readonly supervisor: MockAgent;
  private readonly worker: MockAgent;

  constructor(config: MultiAgentConfig = {}) {
    this.supervisor = createMockAgent(config.supervisor ?? {});
    this.worker = createMockAgent(config.worker ?? {});
  }

  async describeTools(): Promise<ToolSpec[]> {
    return this.worker.describeTools();
  }

  /** Tampering the inter-agent bus — the message reaches the trusting worker. */
  async injectContent(content: InjectedContent): Promise<void> {
    await this.worker.injectContent(content);
  }

  async reset(): Promise<void> {
    await this.supervisor.reset();
    await this.worker.reset();
  }

  async sendMessage(input: AgentInput): Promise<AgentResponse> {
    const sup = await this.supervisor.sendMessage(input);

    // The supervisor delegates the task to the worker over the (untrusted) bus.
    const delegation = `Task delegated by supervisor: ${input.message}`;
    const wrk = await this.worker.sendMessage({ message: delegation });

    const trace: TraceEvent[] = [
      { type: 'note', at: 0, data: { agent: 'supervisor', received: input.message, said: sup.output } },
      { type: 'note', at: 1, data: { hop: 'supervisor→worker', bus: delegation } },
      ...(wrk.trace ?? []),
    ];

    // The supervisor relays the worker's output back to the user verbatim.
    return { output: wrk.output, toolCalls: wrk.toolCalls, trace };
  }
}

export function createMultiAgentMock(config: MultiAgentConfig = {}): MultiAgentMock {
  return new MultiAgentMock(config);
}

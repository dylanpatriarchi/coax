/**
 * Tool allowlisting and human-in-the-loop — least privilege at the tool boundary.
 *
 * The two controls every agent-security guide leads with (OWASP LLM06 Excessive
 * Agency, NIST AI 600-1, Anthropic/OpenAI agent guidance), implemented as one
 * defense because they are the same mechanism with different verdicts:
 *
 *   - DENY — the tool is not on the allowlist, or is explicitly forbidden. The
 *     call never executes.
 *   - HOLD — the tool is high-impact but legitimate, so the call is queued for a
 *     human. In an unattended scan no human is present, so a held call does not
 *     execute either; it is recorded as HELD, not as DENIED, because those are
 *     different operational outcomes and conflating them would flatter the
 *     control.
 *
 * Enforcement is on the OBSERVED call trace: a denied or held call is removed
 * before the oracles see it, which is the honest model of a gateway that refuses
 * to run it. Note the ordering consequence — this defense sits after the agent
 * has already DECIDED to make the call. It measures whether the blast radius was
 * contained, never whether the agent was fooled.
 *
 * WHAT THIS DOES NOT STOP
 *   - Abuse of ALLOWED tools. An agent talked into `read_file` on a path it
 *     should not touch, or into 200 `search_web` calls, passes every check here;
 *     argument-level authorization and rate limits are separate controls.
 *   - Anything in the text channel. Leaked secrets, jailbroken content,
 *     manufactured authority and bad advice involve no tool call at all.
 *   - Rubber-stamping. Modelling HITL as "held, therefore safe" is the control's
 *     best case. Real approval fatigue means a human clicks yes, and COAX cannot
 *     measure that — treat the HITL number as an upper bound.
 *   - The decision itself. The agent still tried. If your threat model includes
 *     an agent that repeatedly attempts forbidden actions, this control hides
 *     the symptom unless you also alert on the denials it records.
 */
import { allow, block } from '../core/defense.js';
import type { Defense, DefenseOutcome } from '../core/defense.js';
import type { AgentResponse, ToolCall } from '../core/target.js';

export interface ToolGuardOptions {
  /** If set, ONLY these tools may execute. Anything else is denied. */
  allow?: readonly string[];
  /** Tools that may never execute, even if allowlisted. */
  deny?: readonly string[];
  /** High-impact tools that require a human decision before executing. */
  requireConfirmation?: readonly string[];
  /**
   * The human. Defaults to refusing: an unattended scan has nobody to ask, and
   * silently auto-approving would measure a control that does not exist.
   */
  confirm?: (call: ToolCall) => boolean;
  /**
   * Refuse the whole turn when a denied tool is attempted, instead of dropping
   * just that call. Models a gateway that fails the request closed.
   */
  blockTurnOnDenial?: boolean;
}

/**
 * Tools whose misuse is irreversible or reaches outside the system. Used when a
 * caller does not supply its own list — deliberately a superset of the mock's
 * forbidden tools so the control is not tuned to COAX's own test double.
 */
export const HIGH_IMPACT_TOOLS: readonly string[] = [
  'send_email',
  'delete_file',
  'run_code',
  'fetch_url',
  'execute',
  'shell',
  'write_file',
  'transfer_funds',
  'post_message',
];

export function createToolGuard(opts: ToolGuardOptions = {}): Defense {
  const allowList = opts.allow ? new Set(opts.allow) : null;
  const denyList = new Set(opts.deny ?? []);
  const confirmList = new Set(opts.requireConfirmation ?? []);
  const confirm = opts.confirm ?? ((): boolean => false);
  const blockTurn = opts.blockTurnOnDenial ?? false;

  const verdictFor = (call: ToolCall): { action: 'run' | 'deny' | 'hold'; why: string } => {
    if (denyList.has(call.name)) return { action: 'deny', why: 'tool is on the deny list' };
    if (allowList && !allowList.has(call.name)) {
      return { action: 'deny', why: 'tool is not on the allowlist' };
    }
    if (confirmList.has(call.name)) {
      return confirm(call)
        ? { action: 'run', why: 'confirmed by a human' }
        : { action: 'hold', why: 'high-impact tool held for human confirmation (none given)' };
    }
    return { action: 'run', why: 'permitted' };
  };

  return {
    id: 'tool-guard',
    description:
      'Least privilege at the tool boundary: denies forbidden or non-allowlisted tools and holds ' +
      'high-impact ones for human confirmation before they can execute.',
    limitations:
      'Enforces only WHICH tool ran, never with what arguments or how often, so abuse of an allowed ' +
      'tool passes unimpeded. Ignores the entire text channel, and models human confirmation as ' +
      'always-correct — a best case that real approval fatigue does not reach.',

    screenOutput(response: AgentResponse): DefenseOutcome<AgentResponse> {
      if (response.toolCalls.length === 0) return allow(response);

      const kept: ToolCall[] = [];
      const notes: string[] = [];
      for (const call of response.toolCalls) {
        const { action, why } = verdictFor(call);
        if (action === 'run') {
          kept.push(call);
          continue;
        }
        if (action === 'deny' && blockTurn) {
          return block(response, `tool-guard denied ${call.name}: ${why}`);
        }
        notes.push(`${action === 'deny' ? 'denied' : 'held'} ${call.name}: ${why}`);
      }

      if (notes.length === 0) return allow(response);
      return allow({ ...response, toolCalls: kept }, notes.join('; '));
    },
  };
}

/**
 * Default instance: no allowlist (so it does not disable tools a target needs),
 * but every high-impact tool requires a confirmation nobody is there to give.
 */
export const toolGuardDefense: Defense = createToolGuard({
  requireConfirmation: HIGH_IMPACT_TOOLS,
});

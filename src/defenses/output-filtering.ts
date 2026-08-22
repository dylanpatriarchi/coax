/**
 * Output filtering — the last line before data leaves the agent.
 *
 * Two mechanisms, both standard in DLP/egress-control practice and both worth
 * measuring separately from input-side controls, because they fail differently:
 *
 *   - CANARY / SECRET REDACTION. Known-secret values (the planted canary, API
 *     keys, the private data field) are matched literally in the response text
 *     and in every tool-call argument and replaced with a marker. This is the
 *     only control here that is genuinely reliable, and only for values you
 *     already know verbatim.
 *   - EGRESS BLOCKING. Tool calls whose arguments carry an external destination
 *     — an off-allowlist URL, an email recipient, a webhook — are removed from
 *     the call trace, modelling a gateway that refuses to execute them. Removal,
 *     not rewriting: a half-executed exfiltration is still an exfiltration.
 *
 * Redaction happens where the agent's output leaves the system, which is why it
 * is modelled as a wrapper on the response rather than a prompt instruction: an
 * instruction not to leak is advice, a filter is a control.
 *
 * WHAT THIS DOES NOT STOP
 *   - Any transformation of the secret. Base64, ROT13, spelling it out one
 *     character per line, describing it, or splitting it across a paragraph all
 *     defeat literal matching. This is exact-match DLP and inherits every one of
 *     its well-known weaknesses.
 *   - Secrets it was never told about. It can only redact values passed in
 *     `secrets`; anything the agent discovers at runtime leaves untouched.
 *   - Egress through channels COAX cannot see. If the target's adapter does not
 *     surface a tool call, this filter never sees it either — and side channels
 *     (DNS, rendered image URLs, a link the human clicks) are invisible here.
 *   - Everything that is not data loss. A jailbroken response, a destructive
 *     `delete_file`, unbounded resource consumption, and manufactured authority
 *     all pass straight through: those are not egress.
 */
import { allow } from '../core/defense.js';
import type { Defense, DefenseOutcome } from '../core/defense.js';
import type { AgentResponse, ToolCall } from '../core/target.js';

export interface OutputFilterOptions {
  /** Literal secret values to redact wherever they appear. */
  secrets?: readonly string[];
  /** Hosts a tool call may legitimately reach. Anything else is egress. */
  allowedHosts?: readonly string[];
  /** Marker substituted for a redacted secret. */
  redactionMarker?: string;
  /**
   * Also redact anything that LOOKS like a credential (long hex/base64 runs,
   * `sk-` style keys). Off by default: it is noisy and can mangle benign output.
   */
  redactSecretShapedStrings?: boolean;
}

const URL_RE = /\bhttps?:\/\/([^\s/"'<>)]+)/gi;
const EMAIL_RE = /\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b/i;
const SECRET_SHAPED_RE = /\b(sk-[A-Za-z0-9]{16,}|[A-Fa-f0-9]{32,}|[A-Za-z0-9+/]{40,}={0,2})\b/g;

const DEFAULT_MARKER = '[REDACTED-BY-OUTPUT-FILTER]';

function hostsIn(text: string): string[] {
  const hosts: string[] = [];
  for (const m of text.matchAll(URL_RE)) {
    const host = (m[1] ?? '').split('@').pop() ?? '';
    if (host) hosts.push(host.toLowerCase());
  }
  return hosts;
}

/** Flatten a tool call's arguments to a single string for scanning. */
function argText(call: ToolCall): string {
  try {
    return JSON.stringify(call.arguments);
  } catch {
    return String(Object.values(call.arguments).join(' '));
  }
}

export function createOutputFilter(opts: OutputFilterOptions = {}): Defense {
  // Longest-first so a secret that contains another is redacted whole.
  const secrets = [...(opts.secrets ?? [])].filter((s) => s.length > 0).sort((a, b) => b.length - a.length);
  const allowedHosts = (opts.allowedHosts ?? []).map((h) => h.toLowerCase());
  const marker = opts.redactionMarker ?? DEFAULT_MARKER;
  const aggressive = opts.redactSecretShapedStrings ?? false;

  const redact = (text: string): string => {
    let out = text;
    for (const s of secrets) out = out.split(s).join(marker);
    if (aggressive) out = out.replace(SECRET_SHAPED_RE, marker);
    return out;
  };

  const isEgress = (call: ToolCall): string | null => {
    const text = argText(call);
    for (const host of hostsIn(text)) {
      if (!allowedHosts.includes(host)) return `external destination ${host}`;
    }
    const email = text.match(EMAIL_RE);
    if (email) return `external recipient ${email[0]}`;
    for (const s of secrets) {
      if (text.includes(s)) return 'a known secret in the call arguments';
    }
    return null;
  };

  return {
    id: 'output-filtering',
    description:
      'Redacts known secrets from the response text and tool-call arguments, and removes tool ' +
      'calls whose arguments carry an off-allowlist external destination.',
    limitations:
      'Exact-match DLP: any encoding, paraphrase or splitting of the secret defeats it, and it can ' +
      'only redact values it was told about. Sees only tool calls the adapter surfaces, and does ' +
      'nothing about non-egress harms (jailbreaks, destructive tools, resource exhaustion).',

    screenOutput(response: AgentResponse): DefenseOutcome<AgentResponse> {
      const notes: string[] = [];

      const redactedOutput = redact(response.output);
      if (redactedOutput !== response.output) notes.push('redacted secret(s) from the response text');

      const kept: ToolCall[] = [];
      for (const call of response.toolCalls) {
        const why = isEgress(call);
        if (why !== null) {
          notes.push(`blocked egress tool call ${call.name}: ${why}`);
          continue;
        }
        const raw = argText(call);
        const redacted = redact(raw);
        if (redacted === raw) {
          kept.push(call);
          continue;
        }
        // Re-parsing can fail if the marker lands somewhere structural; a call we
        // cannot safely rewrite is dropped rather than passed through unredacted.
        try {
          kept.push({ ...call, arguments: JSON.parse(redacted) as Record<string, unknown> });
          notes.push(`redacted secret(s) from ${call.name} arguments`);
        } catch {
          notes.push(`dropped ${call.name}: arguments carried a secret and could not be rewritten`);
        }
      }

      const filtered: AgentResponse = {
        ...response,
        output: redactedOutput,
        toolCalls: kept,
      };
      return notes.length > 0 ? allow(filtered, notes.join('; ')) : allow(filtered);
    },
  };
}

/**
 * Default instance. With no configured secrets it still blocks egress-shaped
 * tool calls — the half of this control that does not need prior knowledge.
 */
export const outputFilteringDefense: Defense = createOutputFilter();

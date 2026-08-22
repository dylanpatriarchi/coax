/**
 * Shared HTTP failure mapping for the LLM clients.
 *
 * A red-team scan that dies with `TypeError: fetch failed` or a raw 401 body is
 * a bad afternoon: the operator can't tell a wrong key from a rate limit from a
 * provider outage, and the judge oracle silently degrades to its heuristic. Both
 * clients therefore funnel every non-2xx and every abort through here so the
 * message names the provider, the status, and the likely fix.
 *
 * Response bodies are truncated and API keys are NEVER interpolated — the key
 * exists only inside the request headers.
 */

export class LlmHttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly provider: string,
  ) {
    super(message);
    this.name = 'LlmHttpError';
  }
}

export class LlmTimeoutError extends Error {
  constructor(provider: string, timeoutMs: number) {
    super(`${provider}: request aborted after ${timeoutMs}ms (timeout)`);
    this.name = 'LlmTimeoutError';
  }
}

/** Keep provider error bodies readable in a console without dumping a novel. */
function snippet(body: string, max = 300): string {
  const flat = body.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

/** Turn a failed `Response` into a typed, actionable error. */
export async function httpError(
  provider: string,
  keyEnvVar: string,
  res: Response,
): Promise<LlmHttpError> {
  const body = snippet(await res.text().catch(() => ''));
  const hint =
    res.status === 401 || res.status === 403
      ? ` — authentication rejected; check ${keyEnvVar}`
      : res.status === 429
        ? ' — rate limited or out of quota; slow down or lower COAX_MAX_LLM_CALLS'
        : res.status >= 500
          ? ' — provider-side failure; retry later'
          : '';
  return new LlmHttpError(`${provider} ${res.status}${hint}: ${body}`, res.status, provider);
}

/** True when a caught error is the AbortController firing our own timeout. */
export function isAbort(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name?: unknown }).name === 'AbortError'
  );
}

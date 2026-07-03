/**
 * Responsible-use gate.
 *
 * Gauntlet is a defensive tool: run it only against agents you own or are
 * explicitly authorized to test. To make misuse harder by accident, any target
 * that is NOT localhost requires an explicit authorization acknowledgement
 * (CLI flag `--i-am-authorized` or env `GAUNTLET_I_AM_AUTHORIZED=true`).
 */

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

/** True if the target string points at the local machine (or is a local file/module). */
export function isLocalTarget(target: string): boolean {
  // A file-path / module target (the mock, a ./target.ts) is local by definition.
  if (!/^https?:\/\//i.test(target)) return true;
  try {
    const host = new URL(target).hostname.toLowerCase();
    return LOCALHOST_HOSTS.has(host) || host.endsWith('.localhost');
  } catch {
    return false;
  }
}

export interface AuthzInput {
  target: string;
  /** From `--i-am-authorized`. */
  flag?: boolean;
  /** From `GAUNTLET_I_AM_AUTHORIZED` (any of true/1/yes). */
  env?: string | undefined;
}

export interface AuthzResult {
  allowed: boolean;
  reason: string;
}

function envIsTruthy(v: string | undefined): boolean {
  if (!v) return false;
  return ['true', '1', 'yes', 'on'].includes(v.trim().toLowerCase());
}

/** Decide whether a scan against `target` may proceed. Pure, so it is unit-testable. */
export function checkAuthorization(input: AuthzInput): AuthzResult {
  if (isLocalTarget(input.target)) {
    return { allowed: true, reason: 'local target — authorization not required' };
  }
  if (input.flag === true || envIsTruthy(input.env)) {
    return { allowed: true, reason: 'authorization acknowledged for remote target' };
  }
  return {
    allowed: false,
    reason:
      'Refusing to scan a non-localhost target without authorization. Only test systems you own ' +
      'or are authorized to test. Re-run with --i-am-authorized (or set ' +
      'GAUNTLET_I_AM_AUTHORIZED=true) to confirm.',
  };
}

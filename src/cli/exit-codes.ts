/**
 * The exit-code contract.
 *
 * WHY: `coax scan` used to exit 0 at 100% ASR, which made COAX unusable as the
 * thing it is most naturally for — a CI gate. Codes are therefore defined once,
 * here, next to the help text that documents them, and treated as PUBLIC API:
 * a pipeline that keys on `3` must keep working across releases.
 *
 *   0  clean — the scan ran and no threshold was breached
 *   1  unexpected error, or bad usage
 *   2  authorization refused (the responsible-use gate said no)
 *   3  policy threshold breached (a finding/ASR/regression limit was exceeded)
 *
 * 2 stays distinct from 3 on purpose: "you may not scan this" and "the scan
 * found something" are different answers and a pipeline must be able to tell
 * them apart.
 */
export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_UNAUTHORIZED = 2;
export const EXIT_POLICY = 3;

/** Rendered verbatim into `coax --help`. */
export const EXIT_CODES_HELP = [
  `  ${EXIT_OK}  clean — the scan ran and no threshold was breached`,
  `  ${EXIT_ERROR}  unexpected error, or bad usage`,
  `  ${EXIT_UNAUTHORIZED}  authorization refused (non-localhost target without --i-am-authorized)`,
  `  ${EXIT_POLICY}  policy threshold breached (--fail-on-severity / --max-asr /`,
  '     --max-weighted-asr / --fail-on-regression)',
];

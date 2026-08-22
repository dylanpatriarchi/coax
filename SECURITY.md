# Security Policy

COAX is an offensive-security tool: it generates attack payloads and runs them
against a target agent. That makes the scope of "a security issue in COAX"
narrower than usual — most of what the tool *does* is intentional. Read the
scope section before filing.

## Supported versions

COAX is pre-1.0. Only the latest published version receives fixes; there are no
backported patch branches.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ current |
| < 0.1   | ❌         |

## Reporting a vulnerability

Report privately through GitHub private security advisories:

**https://github.com/dylanpatriarchi/coax/security/advisories/new**

Do **not** open a public issue, pull request, or discussion for a suspected
vulnerability. The maintainer is [@dylanpatriarchi](https://github.com/dylanpatriarchi).

Include:

- affected version / commit,
- the adapter and configuration involved,
- a minimal reproduction — ideally a seeded `coax scan` invocation, since runs
  are deterministic under `--seed`,
- observed vs. expected behaviour, and the impact you believe it has.

### Response window

| Stage | Target |
|-------|--------|
| Acknowledgement | 72 hours |
| Initial assessment (in scope / severity) | 7 days |
| Fix or mitigation for a confirmed issue | 30 days |

If you do not hear back within 72 hours, ping the advisory thread. Once a fix
ships, the advisory is published and you are credited unless you ask otherwise.
Please hold public disclosure until the advisory is published or 90 days have
passed, whichever comes first.

## Scope

### In scope

- Code execution, path traversal, or file writes triggered by COAX processing
  untrusted input — a target's response, a `--target` module, a poisoned page
  fetched by the Playwright adapter, a report template.
- Leaks of operator secrets: API keys, `.env` contents, or target credentials
  written into `report.md` / `report.html`, logs, or the attack cache.
- Bypasses of the responsible-use gate — anything that lets COAX hit a
  non-localhost target without `--i-am-authorized` /
  `COAX_I_AM_AUTHORIZED=true`.
- Breaking the offline guarantee: a code path that reaches the network during
  `npm test` with `COAX_OFFLINE=1`.
- Supply-chain problems in the published package: unexpected files in `dist`,
  a compromised dependency, a broken provenance attestation.
- Injection into the generated HTML report (a target response that escapes into
  the report and executes when the operator opens it).

### Not in scope

- **The mock agent is deliberately vulnerable.** `src/adapters/mock.ts`, the
  vulnerable multi-agent target, and the fixtures around them exist to be
  exploited — they are the test subject, not the product. Leaking their canary,
  making them call a forbidden tool, or getting them to run code is COAX
  working as designed. Reports of this kind will be closed as out of scope.
- Attack payloads, jailbreak strings, or oracle patterns being "dangerous
  content". Every technique family in COAX is published and documented; the
  payload corpus is the tool.
- A third-party model or agent being successfully attacked by COAX. That is a
  finding about *that* system — report it to its vendor, not here.
- Attack success rates, oracle false positives/negatives, or scoring accuracy.
  Those are correctness bugs: open a normal issue.
- Results from pointing COAX at infrastructure you do not own or are not
  authorized to test. See below.

## Authorized use only

COAX must only be run against systems you own or have explicit, documented
authorization to test. The responsible-use gate exists to make that a
deliberate act, not a default: any non-localhost target requires
`--i-am-authorized` or `COAX_I_AM_AUTHORIZED=true`.

Do not submit reports, scan output, or reproductions derived from unauthorized
testing of third-party systems. Such reports will be closed without action.
Circumventing the gate is itself a vulnerability — report it through the
advisory link above.

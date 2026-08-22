# What this changes

<!-- One paragraph. What behaviour is different after this PR, and why. -->

Closes #

## Type

- [ ] `feat` — new attack module / oracle / adapter / scenario / capability
- [ ] `fix` — incorrect behaviour
- [ ] `docs`
- [ ] `chore` / `ci` / `build`
- [ ] `refactor` / `test`
- [ ] Breaking change (`!` in the subject and a `BREAKING CHANGE:` footer)

## Checks

- [ ] `npm run typecheck`
- [ ] `npm test` (offline)
- [ ] `npm run lint`
- [ ] `npm run format:check`
- [ ] `npm run test:coverage` (thresholds hold — coverage was not lowered)
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/)

## Contract

<!-- Delete the rows that do not apply. -->

- [ ] **Reproducible** — new payloads come from a derived seeded RNG, not a
      hardcoded list; the same seed produces identical output, and existing
      modules' payloads are unchanged.
- [ ] **Deterministic-first** — any new oracle has a deterministic or heuristic
      signal; a judge, if used, has a documented rubric and a non-model fallback.
- [ ] **False positives** — a new oracle is registered in `BUILTIN_ORACLES`, the
      benign corpus gained the adversarially-benign cases for this signal, and
      the FP rate is still 0%.
- [ ] **Offline** — nothing added reaches the network, spawns a model, or reads
      the clock during `npm test` with `COAX_OFFLINE=1`.
- [ ] **Taxonomy** — new modules/payloads carry OWASP LLM 2025 / OWASP Agentic
      2026 / ATLAS ids from `src/core/taxonomy.ts`.
- [ ] **Defenses** — a new defense wraps the target, records a `DefenseEvent`
      with a real `blockedReason` instead of failing silently, and is measured
      against the utility suite as well as ASR.

## Published technique only (attack modules)

- [ ] This implements a **published, documented** technique family. It is not
      novel exploit synthesis and is not tuned against a specific named
      production model.

Reference (paper / advisory / writeup):

<!-- URL + who published it and when. Required for a new attack module. -->

## Scan impact

<!--
If ASR, oracle behaviour, utility, or scoring changed, paste the relevant part of
  npx tsx src/cli/index.ts scan --seed 42
before and after. Otherwise write "none".
-->

```
none
```

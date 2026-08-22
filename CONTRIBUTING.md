# Contributing to COAX

COAX is a measurement tool. Every contribution has to keep three properties
true: runs are **reproducible**, findings are **trustworthy**, and the whole
suite is **offline-testable**. Most of the rules below are that in practice.

Read [SECURITY.md](./SECURITY.md) before reporting anything that looks like a
vulnerability — do not open a public issue for it.

## Dev setup

Node 20+ (CI runs 20, 22 and 24).

```bash
git clone https://github.com/dylanpatriarchi/coax.git
cd coax
npm ci

npm run typecheck     # tsc --noEmit, strict
npm test              # vitest, fully offline
npm run lint          # eslint
npm run format:check  # prettier
npm run test:coverage # vitest + v8 coverage, thresholds enforced
npm run build         # emit dist/
```

`npm run dev -- scan --seed 42` runs the CLI from source without building.

Everything must pass before you open a PR. If the coverage gate trips, add
tests — do not lower the thresholds in `vitest.config.ts` unless you are
deliberately removing covered code, and say so in the PR.

> `src/` is currently excluded from Prettier (`.prettierignore`) — it predates
> the config and gets reformatted in a separate mechanical pass. ESLint still
> covers it. Write new code Prettier-clean anyway.

## The architectural contract

These are not style preferences. A PR that breaks one of them will be asked to
change regardless of how well it works.

### 1. Attack modules are seeded parametric generators, never payload lists

An `AttackModule.generate(ctx)` builds payloads from variant templates plus the
seeded RNG in `ctx.rng`. Derive your own stream (`ctx.rng.derive('my-module')`)
so adding a module never shifts another module's payloads. The same
`(seed, module, context)` must always produce byte-identical payloads — that is
what makes a `report.md` reproducible and a regression bisectable.

A hardcoded array of finished attack strings is not a module. Parameterise:
pretext × demand × delivery, rendered at generation time.

### 2. Oracles are deterministic-first, and must prove ~0% false positives

Ranked by `confidence`:

- `deterministic` — unambiguous (the canary appeared, a forbidden tool fired).
  Prefer this. Always.
- `heuristic` — keyword/regex evidence, no model call.
- `judge` — LLM-as-judge, and **only** with a deterministic or heuristic
  fallback plus a documented rubric, because CI has no model.

Every new oracle must be added to `BUILTIN_ORACLES` in `src/oracles/index.ts`,
which puts it under the false-positive suite in
`src/oracles/false-positive.test.ts`. That test asserts `overallRate === 0`
across `BENIGN_CORPUS`. If your oracle fires on a benign response, the oracle is
wrong — tighten it; do not remove the case.

You must also **extend** `BENIGN_CORPUS` in `src/oracles/false-positive.ts` with
the adversarially-benign cases for your signal: the responses that talk *about*
the thing you detect without doing it (a refusal that says "secret", an
explanation of `rm -rf`, a legitimate call to an allowed tool). An oracle that
only sees easy negatives has not been tested.

Every verdict carries `evidence` — the matched substring, tool name, or judge
rationale. A verdict with no evidence is not usable in a report.

### 3. Everything stays offline-testable

`npm test` runs with `COAX_OFFLINE=1` in CI and must never touch the network,
spawn a model, or depend on wall-clock time. Test against the mock agent
(`src/adapters/mock.ts`) and the multi-agent target. Adapters that talk to real
endpoints (`http`, `openai`, `ollama`, `playwright`) are tested with stubbed
transports. Anything non-deterministic goes through the seeded RNG.

### 4. Everything maps to the taxonomy

Attack modules and payloads carry `taxonomy: TaxonomyId[]` — OWASP LLM Top 10
(2025), OWASP Agentic Top 10 (2026) ASI01–10, and/or MITRE ATLAS. Use existing
ids from `src/core/taxonomy.ts`; adding an id means adding its label there too.
Scoring and the report are built on these.

## Responsible contribution

**Only published, documented technique families.** COAX exists to *measure*
robustness against techniques that are already public — many-shot jailbreak
(Anthropic, 2024), Skeleton Key (Microsoft, 2024), policy puppetry
(HiddenLayer, 2025), and so on. Each module's header comment cites what it
implements.

We do not accept:

- novel exploit synthesis, or attack strings tuned to defeat a specific named
  production model,
- payloads whose only purpose is to elicit genuinely harmful content (weapons,
  CSAM, targeted harassment) — the canary/tool-trace oracles measure control
  failures without needing harmful output,
- techniques with no public reference. A technique proposal that cannot cite a
  paper, vendor advisory, or conference writeup will be closed.

This matches the threat model in the README: the value is measurement, not
weaponisation. If you are unsure which side of the line something falls on, open
a technique proposal issue before writing code.

## Adding an attack module

1. Create `src/attacks/<name>.ts`. Header comment: what the technique is, its
   **public reference**, the surface it targets, and its taxonomy mapping.
2. Export an `AttackModule` — `id`, `family` (extend `AttackFamilySchema` in
   `src/core/attack.ts` only if genuinely new), `description`, `taxonomy`, and
   `generate(ctx)`.
3. In `generate`: derive the RNG (`ctx.rng.derive('<id>')`), shuffle your variant
   and target arrays, respect `ctx.maxPayloads`, and emit payloads with stable
   ids of the form `<id>/<variant>#<index>`. Set `surface`, `severity`,
   `taxonomy`, `technique` and `metadata.variant` on each.
4. Indirect-surface modules populate `payload.inject` (`channel`, `source`,
   `content`) — that content is staged through the adapter's `injectContent`
   before the message is sent.
5. Register it in `BUILTIN_ATTACKS` in `src/attacks/index.ts` and re-export it.
6. Add tests: determinism (same seed → identical payload ids and messages),
   different seed → different ordering, `maxPayloads` respected, taxonomy
   non-empty, and at least one payload landing on the mock agent through the
   oracle you expect to fire.

## Adding an oracle

1. Create `src/oracles/<name>.ts` exporting an `Oracle` — `id`, `description`,
   `confidence`, `evaluate(input)`.
2. `evaluate` reads `input.response` (`output`, `toolCalls`, `trace`),
   `input.canary` and `input.forbiddenTools`. Return an `OracleVerdict` with
   concrete `evidence`.
3. If it needs a judge, expose a `create<Name>Oracle({ model, rubric })` factory
   and keep the default export deterministic so CI works without a model.
4. Register in `BUILTIN_ORACLES` (`src/oracles/index.ts`) and re-export.
5. Add your adversarially-benign cases to `BENIGN_CORPUS` and confirm
   `npm test` still reports a 0% false-positive rate.
6. Add true-positive tests against real mock-agent responses, not synthetic
   strings only.

## Adding an adapter

1. Create `src/adapters/<name>.ts` implementing `TargetAdapter`:
   `name`, `sendMessage`, plus optional `injectContent`, `describeTools` and
   `reset`. Implement `injectContent` if the target can ingest external content
   at all — without it, every indirect-injection module is skipped for that
   target, which silently understates risk.
2. Validate configuration with `zod`. Never read credentials from anywhere but
   the config object or the environment; never log them.
3. Anything non-localhost must go through the responsible-use gate
   (`src/core/authorization.ts`).
4. Export a `create<Name>Agent` factory from `src/adapters/index.ts` and add the
   kind to `ADAPTER_KINDS`.
5. Test with a stubbed transport (see `src/adapters/openai.test.ts`): request
   shaping, response parsing, tool-call surfacing, and staged-content delivery.
   No network in tests.

## Commits and pull requests

[Conventional Commits](https://www.conventionalcommits.org/), lowercase subject,
imperative mood, no trailing period:

```
feat(attacks): add skeleton-key jailbreak module
fix(oracles): stop egress oracle firing on localhost callbacks
docs: document the false-positive corpus contract
chore(ci): run coverage on node 20
test(adapters): cover openai tool-call parsing
```

Scopes in use: `attacks`, `oracles`, `adapters`, `core`, `scenarios`, `report`,
`cli`, `llm`, `ci`. Breaking changes get a `!` and a `BREAKING CHANGE:` footer.

For the PR itself: one logical change per PR, fill in the template, and paste
the relevant `coax scan` output when you change ASR, oracle behaviour, or
scoring. Keep the branch rebased on `main`.

## License

By contributing you agree your work is licensed under the [MIT License](./LICENSE).

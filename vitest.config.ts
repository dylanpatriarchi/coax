import { defineConfig } from 'vitest/config';

/**
 * The suite must be fully offline and deterministic: now that the oracles pick
 * up a judge from the environment, a developer with ANTHROPIC_API_KEY/
 * OPENAI_API_KEY exported would otherwise have `npm test` quietly billing a live
 * model. CI already sets COAX_OFFLINE=1; this makes it true everywhere, and the
 * few tests that exercise the configured path opt out with `vi.stubEnv`.
 *
 * `.claude/` is excluded because agent worktrees live under it: without this,
 * `npm test` from the repo root collects every sibling worktree's copy of the
 * suite and reports a test count that has nothing to do with this checkout.
 */
export default defineConfig({
  test: {
    env: { COAX_OFFLINE: '1' },
    exclude: ['**/node_modules/**', '**/dist/**', '**/.claude/**'],
  },
});

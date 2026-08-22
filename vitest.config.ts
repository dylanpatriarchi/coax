import { defineConfig } from 'vitest/config';

/**
 * The suite must be fully offline and deterministic: now that the oracles pick
 * up a judge from the environment, a developer with ANTHROPIC_API_KEY/
 * OPENAI_API_KEY exported would otherwise have `npm test` quietly billing a live
 * model. CI already sets COAX_OFFLINE=1; this makes it true everywhere, and the
 * few tests that exercise the configured path opt out with `vi.stubEnv`.
 *
 * Colour is forced OFF for the same class of reason: whether the developer runs
 * the suite in a TTY must not change what the CLI prints, so every assertion is
 * written against plain text and a coloured local run cannot pass while CI fails.
 *
 * `.claude/` is excluded because agent worktrees live under it: without this,
 * `npm test` from the repo root collects every sibling worktree's copy of the
 * suite and reports a test count that has nothing to do with this checkout.
 */
export default defineConfig({
  test: {
    env: { COAX_OFFLINE: '1', NO_COLOR: '1' },
    exclude: ['**/node_modules/**', '**/dist/**', '**/.claude/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'lcov', 'json-summary'],
      reportsDirectory: 'coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts'],
      // Thresholds sit ~2pp below the measured numbers (92.4 / 83.8 / 89.5 /
      // 93.4 over 524 tests): the gate catches a real regression without
      // tripping on a one-line change. Raise them when coverage rises; do not
      // lower them to make a red build green.
      thresholds: {
        statements: 90,
        branches: 81,
        functions: 87,
        lines: 91,
      },
    },
  },
});

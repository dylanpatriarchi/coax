// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    // '.claude/**' holds git worktrees: linting them pulls other checkouts'
    // source into this one's report, with errors nobody here can fix.
    ignores: ['dist/**', 'coverage/**', 'node_modules/**', 'report/**', '.claude/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
      },
    },
    rules: {
      // Control and zero-width characters are the subject matter, not typos:
      // the mock agent's sanitiser probe matches them deliberately, and
      // `src/cli/ansi.ts` strips real ANSI escapes so `--no-color` output and
      // test assertions stay byte-comparable. Two sites, both intentional.
      'no-control-regex': 'off',
      // Two sites, both deliberate: a monotonic `step++` on its last read in the
      // mock trace, and an initialiser in the OpenAI adapter that both branches
      // of a try/catch overwrite. Rewriting either to satisfy the rule reads
      // worse; tsc already rejects genuinely unreachable code.
      'no-useless-assignment': 'off',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      eqeqeq: ['error', 'smart'],
    },
  },
  {
    // Tests build deliberately malformed payloads and stub provider responses;
    // `any` there is the point, not an escape hatch.
    files: ['**/*.test.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  prettier,
);

import eslint from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-config-prettier';

export default defineConfig(
  { ignores: ['dist', 'coverage', 'node_modules'] },
  eslint.configs.recommended,
  tseslint.configs.recommended,
  {
    rules: {
      // Allow an unused argument when it is prefixed with "_" (e.g. Express's `_next`).
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  prettier,
);

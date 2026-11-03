import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Tests never read a real .env file: they build their own config.
    env: { NODE_ENV: 'test' },
  },
});

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      NODE_ENV: 'test',
      // Integration tests use a REAL PostgreSQL database (mocks hide constraint bugs).
      // They wipe it between tests, so this must never point at real data.
      DATABASE_URL:
        process.env.TEST_DATABASE_URL ??
        'postgresql://sentinel:sentinel@localhost:5432/sentinel_test',
    },
    // Test files share one database, so they must not run at the same time.
    fileParallelism: false,
  },
});

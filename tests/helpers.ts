import { parseEnv } from '../src/config/env.js';
import { createApp } from '../src/app.js';
import { createLogger } from '../src/lib/logger.js';

// Build an app with a known config, independent of the developer's real .env.
export function buildTestApp(overrides: NodeJS.ProcessEnv = {}) {
  const env = parseEnv({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    CORS_ORIGINS: 'http://localhost:3000',
    ...overrides,
  });
  return createApp(env, createLogger(env));
}

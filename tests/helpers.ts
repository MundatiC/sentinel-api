import request from 'supertest';
import { createApp } from '../src/app.js';
import { parseEnv } from '../src/config/env.js';
import { prisma } from '../src/db/prisma.js';
import { createLogger } from '../src/lib/logger.js';
import { generateApiKey } from '../src/lib/apiKey.js';
import { hashPassword } from '../src/lib/password.js';
import type { Role } from '@prisma/client';

export const TEST_PASSWORD = 'correct-horse-battery-staple';

// Build an app with a known config, independent of the developer's real .env.
export function buildTestApp(overrides: NodeJS.ProcessEnv = {}) {
  const env = parseEnv({
    NODE_ENV: 'test',
    DATABASE_URL: process.env.DATABASE_URL,
    JWT_ACCESS_SECRET: 'test-secret-test-secret-test-secret-123456',
    CORS_ORIGINS: 'http://localhost:3000',
    // High limits so ordinary tests never trip them; the rate-limit test overrides these.
    GLOBAL_RATE_LIMIT: '100000',
    LOGIN_RATE_LIMIT: '100000',
    ...overrides,
  });
  return { app: createApp(env, createLogger(env)), env };
}

// Wipe every table. TRUNCATE (unlike DELETE) skips the audit-log immutability trigger.
export async function resetDb() {
  const tables = await prisma.$queryRaw<{ tablename: string }[]>`
    SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename <> '_prisma_migrations'`;
  const list = tables.map((t) => `"${t.tablename}"`).join(', ');
  await prisma.$executeRawUnsafe(`TRUNCATE ${list} RESTART IDENTITY CASCADE`);
}

export async function createUser(email: string, role: Role = 'VIEWER', password = TEST_PASSWORD) {
  return prisma.user.create({
    data: { email, role, passwordHash: await hashPassword(password) },
  });
}

export async function loginAs(
  app: Parameters<typeof request>[0],
  email: string,
  password = TEST_PASSWORD,
) {
  const res = await request(app).post('/api/v1/auth/login').send({ email, password });
  const cookie = (res.headers['set-cookie'] as unknown as string[] | undefined)?.[0]?.split(';')[0];
  return { res, accessToken: res.body.accessToken as string, cookie: cookie as string };
}

// Creates an API key straight in the database (bypassing the admin endpoint) and returns the raw key.
export async function createApiKey(
  scopes: string[] = ['events:write', 'scans:write'],
  overrides: { expiresAt?: Date; revokedAt?: Date } = {},
) {
  const admin = await prisma.user.upsert({
    where: { email: 'keyowner@example.com' },
    update: {},
    create: { email: 'keyowner@example.com', role: 'ADMIN', passwordHash: 'x' },
  });
  const { raw, prefix, hash } = generateApiKey();
  const key = await prisma.apiKey.create({
    data: { name: 'test key', prefix, keyHash: hash, scopes, createdById: admin.id, ...overrides },
  });
  return { raw, key };
}

export function sampleEvent(overrides: Record<string, unknown> = {}) {
  return {
    type: 'auth.login_failed',
    severity: 'MEDIUM',
    source: 'web-1',
    actor: 'alice',
    ip: '203.0.113.7',
    message: 'Failed login for alice',
    ...overrides,
  };
}

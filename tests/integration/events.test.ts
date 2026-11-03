import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createUser, loginAs, resetDb } from '../helpers.js';

const { app } = buildTestApp();

beforeEach(resetDb);

async function viewerToken() {
  await createUser('viewer@example.com', 'VIEWER');
  const { accessToken } = await loginAs(app, 'viewer@example.com');
  // Logging in records a self-monitoring event; clear it so each test controls its own data.
  await prisma.event.deleteMany();
  return accessToken;
}

const at = (iso: string) => new Date(iso);
async function seedEvents() {
  await prisma.event.createMany({
    data: [
      {
        type: 'auth.login_failed',
        severity: 'MEDIUM',
        source: 'web-1',
        actor: 'alice',
        ip: '203.0.113.7',
        message: 'Failed login for alice',
        occurredAt: at('2026-01-01T10:05:00Z'),
      },
      {
        type: 'auth.login_failed',
        severity: 'HIGH',
        source: 'web-2',
        actor: 'bob',
        ip: '203.0.113.8',
        message: 'Failed login for bob',
        occurredAt: at('2026-01-01T10:20:00Z'),
      },
      {
        type: 'http.injection_attempt',
        severity: 'CRITICAL',
        source: 'web-1',
        ip: '203.0.113.7',
        message: "GET /?id=1' OR 1=1",
        occurredAt: at('2026-01-01T11:10:00Z'),
      },
      {
        type: 'auth.login_success',
        severity: 'INFO',
        source: 'web-1',
        actor: 'alice',
        message: '100% success rate',
        occurredAt: at('2026-01-02T09:00:00Z'),
      },
    ],
  });
}
const get = (token: string, url: string) =>
  request(app).get(url).set('Authorization', `Bearer ${token}`);

describe('GET /events', () => {
  it('requires authentication', async () => {
    expect((await request(app).get('/api/v1/events')).status).toBe(401);
  });

  it('lists newest first with pagination metadata', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(token, '/api/v1/events?pageSize=3');
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(3);
    expect(res.body.data[0].message).toBe('100% success rate');
    expect(res.body.pagination).toEqual({ page: 1, pageSize: 3, total: 4, totalPages: 2 });
    const page2 = await get(token, '/api/v1/events?pageSize=3&page=2');
    expect(page2.body.data).toHaveLength(1);
  });

  it('sorts ascending when asked', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(token, '/api/v1/events?sort=occurredAt:asc');
    expect(res.body.data[0].actor).toBe('alice');
    expect(res.body.data[0].message).toBe('Failed login for alice');
  });

  it('filters by type, ip, actor, source and combinations', async () => {
    const token = await viewerToken();
    await seedEvents();
    expect((await get(token, '/api/v1/events?type=auth.login_failed')).body.pagination.total).toBe(
      2,
    );
    expect((await get(token, '/api/v1/events?ip=203.0.113.7')).body.pagination.total).toBe(2);
    expect((await get(token, '/api/v1/events?actor=bob')).body.pagination.total).toBe(1);
    expect(
      (await get(token, '/api/v1/events?source=web-1&type=auth.login_failed')).body.pagination
        .total,
    ).toBe(1);
  });

  it('filters by one or several severities', async () => {
    const token = await viewerToken();
    await seedEvents();
    expect((await get(token, '/api/v1/events?severity=HIGH')).body.pagination.total).toBe(1);
    expect((await get(token, '/api/v1/events?severity=high,critical')).body.pagination.total).toBe(
      2,
    );
    expect((await get(token, '/api/v1/events?severity=NOPE')).status).toBe(400);
  });

  it('filters by date range', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(
      token,
      '/api/v1/events?from=2026-01-01T10:00:00Z&to=2026-01-01T10:30:00Z',
    );
    expect(res.body.pagination.total).toBe(2);
  });

  it('searches the message case-insensitively', async () => {
    const token = await viewerToken();
    await seedEvents();
    expect((await get(token, '/api/v1/events?q=FAILED')).body.pagination.total).toBe(2);
  });

  it('treats % and _ in the search as literal characters, not wildcards', async () => {
    const token = await viewerToken();
    await seedEvents();
    expect(
      (await get(token, '/api/v1/events?q=' + encodeURIComponent('100%'))).body.pagination.total,
    ).toBe(1);
    expect(
      (await get(token, '/api/v1/events?q=' + encodeURIComponent('%'))).body.pagination.total,
    ).toBe(1);
    expect(
      (await get(token, '/api/v1/events?q=' + encodeURIComponent('_'))).body.pagination.total,
    ).toBe(0);
  });

  it('is safe against SQL injection in filters', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(token, '/api/v1/events?source=' + encodeURIComponent("x' OR '1'='1"));
    expect(res.status).toBe(200);
    expect(res.body.pagination.total).toBe(0);
    expect(await prisma.event.count()).toBe(4);
  });

  it.each([
    'page=0',
    'pageSize=101',
    'pageSize=abc',
    'ip=not-an-ip',
    'from=yesterday',
    'sort=password:asc',
  ])('rejects invalid query %s', async (query) => {
    const token = await viewerToken();
    expect((await get(token, `/api/v1/events?${query}`)).status).toBe(400);
  });
});

describe('GET /events/:id', () => {
  it('returns one event, 404 for unknown, 400 for a malformed id', async () => {
    const token = await viewerToken();
    await seedEvents();
    const first = await prisma.event.findFirstOrThrow();
    expect((await get(token, `/api/v1/events/${first.id}`)).body.event.id).toBe(first.id);
    expect((await get(token, '/api/v1/events/00000000-0000-4000-8000-000000000000')).status).toBe(
      404,
    );
    expect((await get(token, '/api/v1/events/abc')).status).toBe(400);
  });
});

describe('GET /events/stats', () => {
  it('groups counts per hour and severity', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(
      token,
      '/api/v1/events/stats?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&bucket=hour',
    );
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual([
      expect.objectContaining({ bucket: '2026-01-01T10:00:00.000Z', MEDIUM: 1, HIGH: 1, total: 2 }),
      expect.objectContaining({ bucket: '2026-01-01T11:00:00.000Z', CRITICAL: 1, total: 1 }),
    ]);
  });

  it('can group per day', async () => {
    const token = await viewerToken();
    await seedEvents();
    const res = await get(
      token,
      '/api/v1/events/stats?from=2026-01-01T00:00:00Z&to=2026-01-03T00:00:00Z&bucket=day',
    );
    expect(res.body.data.map((row: { total: number }) => row.total)).toEqual([3, 1]);
  });

  it('validates the range and bucket', async () => {
    const token = await viewerToken();
    expect((await get(token, '/api/v1/events/stats?bucket=minute')).status).toBe(400);
    expect(
      (await get(token, '/api/v1/events/stats?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z'))
        .status,
    ).toBe(400);
    expect(
      (await get(token, '/api/v1/events/stats?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z'))
        .status,
    ).toBe(400);
  });
});

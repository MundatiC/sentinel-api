import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createApiKey, resetDb, sampleEvent } from '../helpers.js';

const { app } = buildTestApp();

beforeEach(resetDb);

const postEvents = (key: string | undefined, body: unknown) => {
  const req = request(app).post('/api/v1/ingest/events');
  if (key) req.set('X-API-Key', key);
  return req.send(body as object);
};

describe('API key authentication on ingest', () => {
  it('rejects a missing key, a malformed key and a wrong secret with the same 401', async () => {
    const { raw } = await createApiKey();
    const wrongSecret = raw.slice(0, -3) + 'abc';
    for (const key of [undefined, 'garbage', wrongSecret]) {
      const res = await postEvents(key, { events: [sampleEvent()] });
      expect(res.status).toBe(401);
      expect(res.body.error.message).toBe('Invalid API key');
    }
  });

  it('rejects expired and revoked keys', async () => {
    const expired = await createApiKey(['events:write'], {
      expiresAt: new Date(Date.now() - 1000),
    });
    const revoked = await createApiKey(['events:write'], { revokedAt: new Date() });
    expect((await postEvents(expired.raw, { events: [sampleEvent()] })).status).toBe(401);
    expect((await postEvents(revoked.raw, { events: [sampleEvent()] })).status).toBe(401);
  });

  it('enforces scopes', async () => {
    const { raw } = await createApiKey(['scans:write']);
    const res = await postEvents(raw, { events: [sampleEvent()] });
    expect(res.status).toBe(403);
  });

  it('an API key cannot be used on user endpoints', async () => {
    const { raw } = await createApiKey();
    const res = await request(app).get('/api/v1/events').set('X-API-Key', raw);
    expect(res.status).toBe(401);
  });

  it('updates lastUsedAt', async () => {
    const { raw, key } = await createApiKey();
    await postEvents(raw, { events: [sampleEvent()] });
    expect(
      (await prisma.apiKey.findUniqueOrThrow({ where: { id: key.id } })).lastUsedAt,
    ).not.toBeNull();
  });

  it('rejects unauthenticated callers before reading a large body', async () => {
    const res = await postEvents(undefined, {
      events: [sampleEvent({ message: 'x'.repeat(900_000) })],
    });
    expect(res.status).toBe(401);
  });
});

describe('POST /ingest/events', () => {
  it('stores a batch and links it to the key', async () => {
    const { raw, key } = await createApiKey();
    const res = await postEvents(raw, {
      events: [sampleEvent(), sampleEvent({ actor: 'bob', severity: undefined })],
    });
    expect(res.status).toBe(201);
    expect(res.body.accepted).toBe(2);
    const stored = await prisma.event.findMany({ orderBy: { actor: 'asc' } });
    expect(stored).toHaveLength(2);
    expect(stored[0]).toMatchObject({
      actor: 'alice',
      apiKeyId: key.id,
      severity: 'MEDIUM',
      ip: '203.0.113.7',
    });
    expect(stored[1]!.severity).toBe('INFO'); // default
  });

  it.each([
    ['empty batch', { events: [] }],
    ['unknown field', { events: [sampleEvent({ admin: true })] }],
    ['bad event type', { events: [sampleEvent({ type: 'DROP TABLE' })] }],
    ['bad ip', { events: [sampleEvent({ ip: '999.1.1.1' })] }],
    ['bad severity', { events: [sampleEvent({ severity: 'SCARY' })] }],
    ['empty message', { events: [sampleEvent({ message: '' })] }],
    [
      'timestamp in the future',
      { events: [sampleEvent({ occurredAt: new Date(Date.now() + 3_600_000).toISOString() })] },
    ],
    ['oversized metadata', { events: [sampleEvent({ metadata: { blob: 'x'.repeat(9000) } })] }],
    ['missing wrapper', sampleEvent()],
  ])('rejects %s', async (_name, body) => {
    const { raw } = await createApiKey();
    const res = await postEvents(raw, body);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
    expect(await prisma.event.count()).toBe(0); // all-or-nothing
  });

  it('rejects more than 500 events', async () => {
    const { raw } = await createApiKey();
    const res = await postEvents(raw, { events: Array.from({ length: 501 }, () => sampleEvent()) });
    expect(res.status).toBe(400);
  });

  it('accepts 500 events', async () => {
    const { raw } = await createApiKey();
    const res = await postEvents(raw, { events: Array.from({ length: 500 }, () => sampleEvent()) });
    expect(res.status).toBe(201);
    expect(await prisma.event.count()).toBe(500);
  });

  it('keeps hostile text as inert data (XSS / SQL strings are stored verbatim)', async () => {
    const { raw } = await createApiKey();
    const nasty = `<script>alert(1)</script>'; DROP TABLE "Event"; --`;
    expect((await postEvents(raw, { events: [sampleEvent({ message: nasty })] })).status).toBe(201);
    expect((await prisma.event.findFirstOrThrow()).message).toBe(nasty);
  });

  it('rate limits per API key', async () => {
    const { app: strict } = buildTestApp({ INGEST_RATE_LIMIT: '2' });
    const { raw } = await createApiKey();
    const send = () =>
      request(strict)
        .post('/api/v1/ingest/events')
        .set('X-API-Key', raw)
        .send({ events: [sampleEvent()] });
    expect((await send()).status).toBe(201);
    expect((await send()).status).toBe(201);
    expect((await send()).status).toBe(429);
  });
});

describe('POST /ingest/scans', () => {
  const finding = (overrides: Record<string, unknown> = {}) => ({
    checkId: 'headers.hsts_missing',
    category: 'HEADERS',
    severity: 'MEDIUM',
    title: 'HSTS header missing',
    description: 'No Strict-Transport-Security header.',
    remediation: 'Add the header.',
    references: ['https://owasp.org/www-project-secure-headers/'],
    ...overrides,
  });
  const scan = (findings: unknown[], overrides: Record<string, unknown> = {}) => ({
    target: 'https://example.com',
    scannerVersion: '0.1.0',
    startedAt: '2026-01-01T10:00:00Z',
    finishedAt: '2026-01-01T10:00:30Z',
    findings,
    ...overrides,
  });
  const postScan = (key: string, body: unknown) =>
    request(app)
      .post('/api/v1/ingest/scans')
      .set('X-API-Key', key)
      .send(body as object);

  it('stores the scan, findings and severity summary; critical findings become events', async () => {
    const { raw } = await createApiKey();
    const res = await postScan(
      raw,
      scan([
        finding(),
        finding({
          checkId: 'files.git_exposed',
          category: 'EXPOSED_FILES',
          severity: 'CRITICAL',
          title: '.git exposed',
        }),
      ]),
    );
    expect(res.status).toBe(201);
    expect(res.body.summary).toMatchObject({ MEDIUM: 1, CRITICAL: 1, HIGH: 0 });
    expect(res.body.criticalEvents).toBe(1);

    expect(await prisma.scanFinding.count({ where: { scanId: res.body.id } })).toBe(2);
    const event = await prisma.event.findFirstOrThrow();
    expect(event).toMatchObject({
      type: 'scan.finding_critical',
      severity: 'CRITICAL',
      source: 'example.com',
      message: '.git exposed',
    });
  });

  it('accepts a local:// target for dependency scans and uses the project name as the event source', async () => {
    const { raw } = await createApiKey();
    const res = await postScan(
      raw,
      scan(
        [
          finding({
            checkId: 'deps.GHSA-aaaa-bbbb-cccc',
            category: 'DEPENDENCIES',
            severity: 'CRITICAL',
          }),
        ],
        {
          target: 'local://my-project',
        },
      ),
    );
    expect(res.status).toBe(201);
    expect((await prisma.event.findFirstOrThrow()).source).toBe('my-project');
  });

  it.each([
    ['non-http target', scan([], { target: 'file:///etc/passwd' })],
    ['javascript: target', scan([], { target: 'javascript:alert(1)' })],
    ['finish before start', scan([], { finishedAt: '2025-01-01T00:00:00Z' })],
    ['bad category', scan([finding({ category: 'MAGIC' })])],
    ['javascript: reference', scan([finding({ references: ['javascript:alert(1)'] })])],
  ])('rejects %s', async (_name, body) => {
    const { raw } = await createApiKey();
    expect((await postScan(raw, body)).status).toBe(400);
    expect(await prisma.scan.count()).toBe(0);
  });

  it('requires the scans:write scope', async () => {
    const { raw } = await createApiKey(['events:write']);
    expect((await postScan(raw, scan([]))).status).toBe(403);
  });
});

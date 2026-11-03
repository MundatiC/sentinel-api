import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { alertBus, type AlertMessage } from '../../src/modules/alerts/alertBus.js';
import {
  buildTestApp,
  createApiKey,
  createUser,
  resetDb,
  sampleEvent,
  seedDefaultRules,
  TEST_PASSWORD,
} from '../helpers.js';

const { app } = buildTestApp();

beforeEach(async () => {
  await resetDb();
  await seedDefaultRules();
});

const ago = (seconds: number) => new Date(Date.now() - seconds * 1000).toISOString();
const failed = (overrides: Record<string, unknown> = {}) =>
  sampleEvent({ type: 'auth.login_failed', ...overrides });

async function ingest(key: string, events: object[]) {
  const res = await request(app)
    .post('/api/v1/ingest/events')
    .set('X-API-Key', key)
    .send({ events });
  expect(res.status).toBe(201);
}

describe('threshold rules', () => {
  it('stays quiet below the threshold and alerts at it', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 4 }, () => failed()),
    );
    expect(await prisma.alert.count()).toBe(0);

    await ingest(raw, [failed()]);
    const alert = await prisma.alert.findFirstOrThrow({ include: { rule: true } });
    expect(alert).toMatchObject({
      status: 'OPEN',
      severity: 'HIGH',
      groupKey: '203.0.113.7',
      eventCount: 5,
      title: 'Brute-force login attempts: 203.0.113.7',
    });
    expect(await prisma.alertEvent.count({ where: { alertId: alert.id } })).toBe(5);
  });

  it('raises ONE alert for a single batch that crosses the threshold', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 8 }, () => failed()),
    );
    const alerts = await prisma.alert.findMany();
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.eventCount).toBe(8);
  });

  it('adds later events to the same active alert instead of creating duplicates', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    await ingest(raw, [failed(), failed()]);
    const alerts = await prisma.alert.findMany();
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.eventCount).toBe(7);
  });

  it('only counts events inside the time window', async () => {
    const { raw } = await createApiKey();
    // 5 events, but spread over 5 minutes: never 5 within any 60 seconds.
    await ingest(
      raw,
      [0, 70, 140, 210, 280].map((s) => failed({ occurredAt: ago(s) })),
    );
    expect(await prisma.alert.count()).toBe(0);
  });

  it('keeps different IPs separate', async () => {
    const { raw } = await createApiKey();
    const events = [
      ...Array.from({ length: 3 }, () => failed({ ip: '198.51.100.1' })),
      ...Array.from({ length: 3 }, () => failed({ ip: '198.51.100.2' })),
    ];
    await ingest(raw, events);
    expect(await prisma.alert.count()).toBe(0);
    await ingest(raw, [failed({ ip: '198.51.100.1' }), failed({ ip: '198.51.100.1' })]);
    expect((await prisma.alert.findFirstOrThrow()).groupKey).toBe('198.51.100.1');
  });

  it('ignores events that lack the group-by field', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 6 }, () => failed({ ip: undefined })),
    );
    expect(await prisma.alert.count()).toBe(0);
  });

  it('does not fire for disabled rules', async () => {
    await prisma.alertRule.updateMany({ data: { enabled: false } });
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 6 }, () => failed()),
    );
    expect(await prisma.alert.count()).toBe(0);
  });

  it('uses the rule for the right event type', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 3 }, () => sampleEvent({ type: 'http.injection_attempt' })),
    );
    const alert = await prisma.alert.findFirstOrThrow();
    expect(alert.severity).toBe('CRITICAL');
  });

  it('supports rules that group by source (critical scan findings)', async () => {
    const { raw } = await createApiKey();
    const res = await request(app)
      .post('/api/v1/ingest/scans')
      .set('X-API-Key', raw)
      .send({
        target: 'https://example.com',
        scannerVersion: '0.1.0',
        startedAt: ago(30),
        finishedAt: ago(1),
        findings: [
          {
            checkId: 'files.git_exposed',
            category: 'EXPOSED_FILES',
            severity: 'CRITICAL',
            title: '.git exposed',
            description: 'd',
            remediation: 'r',
          },
        ],
      });
    expect(res.status).toBe(201);
    const alert = await prisma.alert.findFirstOrThrow();
    expect(alert).toMatchObject({ groupKey: 'example.com', severity: 'CRITICAL' });
  });

  it('a read-only change to a rule applies to the next ingest', async () => {
    const { raw } = await createApiKey();
    await prisma.alertRule.updateMany({
      where: { eventType: 'auth.login_failed' },
      data: { threshold: 2 },
    });
    await ingest(raw, [failed(), failed()]);
    expect(await prisma.alert.count()).toBe(1);
  });
});

describe('alert lifecycle', () => {
  it('adds events to an ACKNOWLEDGED alert rather than opening a second one', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    await prisma.alert.updateMany({ data: { status: 'ACKNOWLEDGED' } });
    await ingest(raw, [failed()]);
    const alerts = await prisma.alert.findMany();
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.eventCount).toBe(6);
  });

  it('respects the cooldown after an alert is resolved, then alerts again', async () => {
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    await prisma.alert.updateMany({ data: { status: 'RESOLVED', resolvedAt: new Date() } });

    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    expect(await prisma.alert.count()).toBe(1); // still cooling down (300 s)

    await prisma.alert.updateMany({ data: { resolvedAt: new Date(Date.now() - 600_000) } });
    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    expect(await prisma.alert.count()).toBe(2);
  });

  it('never creates duplicate open alerts under concurrent ingestion', async () => {
    const { raw } = await createApiKey();
    // Two requests, each 3 events: neither alone reaches 5, together they do. Run at the same time.
    await Promise.all([
      ingest(
        raw,
        Array.from({ length: 3 }, () => failed()),
      ),
      ingest(
        raw,
        Array.from({ length: 3 }, () => failed()),
      ),
    ]);
    expect(await prisma.alert.count({ where: { status: 'OPEN' } })).toBeLessThanOrEqual(1);
    // Whichever request evaluated last saw all 6 events:
    const alert = await prisma.alert.findFirstOrThrow();
    expect(alert.eventCount).toBeGreaterThanOrEqual(5);
  });
});

describe('live publishing', () => {
  it('publishes alert.created then alert.updated on the bus', async () => {
    const messages: AlertMessage[] = [];
    const unsubscribe = alertBus.subscribe((m) => messages.push(m));
    const { raw } = await createApiKey();
    await ingest(
      raw,
      Array.from({ length: 5 }, () => failed()),
    );
    await ingest(raw, [failed()]);
    unsubscribe();
    expect(messages.map((m) => m.type)).toEqual(['alert.created', 'alert.updated']);
    expect(messages[0]!.alert).toMatchObject({
      ruleName: 'Brute-force login attempts',
      severity: 'HIGH',
    });
  });
});

describe('self-monitoring', () => {
  it('turns failed Sentinel logins into events that trigger the brute-force rule', async () => {
    await createUser('victim@example.com');
    const attempt = () =>
      request(app)
        .post('/api/v1/auth/login')
        .send({ email: 'victim@example.com', password: 'wrong-password-123' });
    for (let i = 0; i < 4; i++) await attempt();
    expect(await prisma.alert.count()).toBe(0);
    await attempt();

    const alert = await prisma.alert.findFirstOrThrow();
    expect(alert.title).toContain('Brute-force login attempts');
    const events = await prisma.event.findMany({ where: { type: 'auth.login_failed' } });
    expect(events).toHaveLength(5);
    expect(events[0]).toMatchObject({ source: 'sentinel-api', actor: 'victim@example.com' });
    // The password is never written into the event.
    expect(JSON.stringify(events)).not.toContain('wrong-password-123');
  });

  it('records successful logins as INFO events', async () => {
    await createUser('ok@example.com');
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ok@example.com', password: TEST_PASSWORD });
    expect(
      await prisma.event.count({ where: { type: 'auth.login_success', severity: 'INFO' } }),
    ).toBe(1);
  });
});

import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { resetDemo, seedDemo } from '../../src/scripts/demo-data.js';
import { createUser, resetDb } from '../helpers.js';

beforeEach(resetDb);

const counts = async () => ({
  events: await prisma.event.count(),
  alerts: await prisma.alert.count(),
  incidents: await prisma.incident.count(),
  scans: await prisma.scan.count(),
  findings: await prisma.scanFinding.count(),
});

describe('demo data', () => {
  it('creates alerts in every status, an incident with a timeline, and scan history that improves', async () => {
    await seedDemo();

    const alerts = await prisma.alert.findMany({ include: { events: true } });
    expect(new Set(alerts.map((a) => a.status))).toEqual(
      new Set(['OPEN', 'ACKNOWLEDGED', 'RESOLVED']),
    );
    // each alert is linked to exactly the events that triggered it
    expect(alerts.every((a) => a.events.length === a.eventCount)).toBe(true);

    const incident = await prisma.incident.findFirstOrThrow({
      include: { timeline: true, alerts: true },
    });
    expect(incident.alerts).toHaveLength(2);
    expect(incident.timeline.length).toBeGreaterThanOrEqual(5);

    const shop = await prisma.scan.findMany({
      where: { target: 'https://shop.demo.example/' },
      orderBy: { finishedAt: 'asc' },
    });
    expect(shop).toHaveLength(4);
    const total = (s: { summary: unknown }) =>
      Object.values(s.summary as Record<string, number>).reduce((a, b) => a + b, 0);
    expect(total(shop[0]!)).toBeGreaterThan(total(shop[3]!)); // fewer findings over time
  });

  it('uses only reserved documentation addresses and the demo analyst cannot sign in', async () => {
    await seedDemo();
    const ips = (await prisma.event.findMany({ select: { ip: true } }))
      .map((e) => e.ip)
      .filter((ip): ip is string => ip !== null);
    expect(ips.every((ip) => /^(203\.0\.113|198\.51\.100|192\.0\.2)\./.test(ip))).toBe(true);
    const analyst = await prisma.user.findFirstOrThrow({ where: { role: 'ANALYST' } });
    expect(analyst.email).toMatch(/\.example$/);
  });

  it('is repeatable: seeding twice refreshes the data instead of duplicating it', async () => {
    await seedDemo();
    const first = await counts();
    await seedDemo();
    expect(await counts()).toEqual(first);
  });

  it('reset removes only the demo data and leaves real data alone', async () => {
    await createUser('real-admin@example.com', 'ADMIN');
    await prisma.event.create({
      data: {
        type: 'auth.login_failed',
        source: 'real-app',
        message: 'a real event',
        occurredAt: new Date(),
      },
    });
    await prisma.scan.create({
      data: {
        target: 'https://real-site.com/',
        scannerVersion: '0.1.0',
        startedAt: new Date(),
        finishedAt: new Date(),
      },
    });

    await seedDemo();
    await resetDemo();

    expect(await counts()).toEqual({ events: 1, alerts: 0, incidents: 0, scans: 1, findings: 0 });
    expect(await prisma.user.findMany({ select: { email: true } })).toEqual([
      { email: 'real-admin@example.com' },
    ]);
  });
});

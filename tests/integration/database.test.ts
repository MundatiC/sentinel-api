import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, resetDb } from '../helpers.js';

const { app } = buildTestApp();

beforeEach(resetDb);

describe('GET /ready', () => {
  it('reports ready when the database answers', async () => {
    const res = await request(app).get('/api/v1/ready');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
  });
});

describe('audit log immutability', () => {
  it('rejects UPDATE and DELETE at the database level', async () => {
    const row = await prisma.auditLog.create({
      data: { actorType: 'SYSTEM', action: 'test.entry' },
    });
    await expect(
      prisma.auditLog.update({ where: { id: row.id }, data: { action: 'tampered' } }),
    ).rejects.toThrow(/append-only/);
    await expect(prisma.auditLog.delete({ where: { id: row.id } })).rejects.toThrow(/append-only/);
  });
});

describe('alert dedup index', () => {
  it('allows only one OPEN alert per rule and group key', async () => {
    const rule = await prisma.alertRule.create({
      data: { name: 'r', eventType: 't', threshold: 1, windowSeconds: 60, severity: 'HIGH' },
    });
    const alert = {
      ruleId: rule.id,
      title: 'a',
      groupKey: '1.2.3.4',
      severity: 'HIGH' as const,
      firstEventAt: new Date(),
      lastEventAt: new Date(),
    };
    const first = await prisma.alert.create({ data: alert });
    await expect(prisma.alert.create({ data: alert })).rejects.toThrow();
    // Once resolved, a new open alert for the same key is allowed again.
    await prisma.alert.update({ where: { id: first.id }, data: { status: 'RESOLVED' } });
    await expect(prisma.alert.create({ data: alert })).resolves.toBeTruthy();
  });
});

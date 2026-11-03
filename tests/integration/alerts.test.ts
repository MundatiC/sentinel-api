import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createUser, loginAs, resetDb } from '../helpers.js';

const { app } = buildTestApp();
beforeEach(resetDb);

async function tokenFor(email: string, role: 'ADMIN' | 'ANALYST' | 'VIEWER') {
  await createUser(email, role);
  return (await loginAs(app, email)).accessToken;
}
const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

async function makeAlert(overrides: Record<string, unknown> = {}) {
  const rule = await prisma.alertRule.upsert({
    where: { name: 'rule' },
    update: {},
    create: {
      name: 'rule',
      eventType: 'auth.login_failed',
      threshold: 5,
      windowSeconds: 60,
      severity: 'HIGH',
    },
  });
  const event = await prisma.event.create({
    data: {
      type: 'auth.login_failed',
      source: 's',
      message: 'm',
      ip: '1.1.1.1',
      occurredAt: new Date(),
    },
  });
  const alert = await prisma.alert.create({
    data: {
      ruleId: rule.id,
      title: 'Brute force: 1.1.1.1',
      groupKey: '1.1.1.1',
      severity: 'HIGH',
      eventCount: 1,
      firstEventAt: new Date(),
      lastEventAt: new Date(),
      events: { create: { eventId: event.id } },
      ...overrides,
    },
  });
  return alert;
}

describe('GET /alerts', () => {
  it('requires auth and lists with rule name, filters and pagination', async () => {
    expect((await request(app).get('/api/v1/alerts')).status).toBe(401);
    const token = await tokenFor('v@example.com', 'VIEWER');
    await makeAlert();
    await makeAlert({ groupKey: '2.2.2.2', status: 'RESOLVED', severity: 'LOW' });

    const all = await request(app).get('/api/v1/alerts').set(auth(token));
    expect(all.body.pagination.total).toBe(2);
    expect(all.body.data[0].rule.name).toBe('rule');
    expect(
      (await request(app).get('/api/v1/alerts?status=OPEN').set(auth(token))).body.pagination.total,
    ).toBe(1);
    expect(
      (await request(app).get('/api/v1/alerts?status=open,resolved').set(auth(token))).body
        .pagination.total,
    ).toBe(2);
    expect(
      (await request(app).get('/api/v1/alerts?severity=LOW').set(auth(token))).body.pagination
        .total,
    ).toBe(1);
    expect((await request(app).get('/api/v1/alerts?status=BOGUS').set(auth(token))).status).toBe(
      400,
    );
  });
});

describe('GET /alerts/:id', () => {
  it('returns the alert with its triggering events', async () => {
    const token = await tokenFor('v@example.com', 'VIEWER');
    const alert = await makeAlert();
    const res = await request(app).get(`/api/v1/alerts/${alert.id}`).set(auth(token));
    expect(res.status).toBe(200);
    expect(res.body.alert.events).toHaveLength(1);
    expect(res.body.alert.rule.name).toBe('rule');
    expect(
      (
        await request(app)
          .get('/api/v1/alerts/00000000-0000-4000-8000-000000000000')
          .set(auth(token))
      ).status,
    ).toBe(404);
  });
});

describe('PATCH /alerts/:id', () => {
  it('is analyst-only', async () => {
    const token = await tokenFor('v@example.com', 'VIEWER');
    const alert = await makeAlert();
    expect(
      (
        await request(app)
          .patch(`/api/v1/alerts/${alert.id}`)
          .set(auth(token))
          .send({ status: 'ACKNOWLEDGED' })
      ).status,
    ).toBe(403);
  });

  it('acknowledges then resolves, recording who and when, with audit entries', async () => {
    const token = await tokenFor('a@example.com', 'ANALYST');
    const me = await prisma.user.findFirstOrThrow({ where: { email: 'a@example.com' } });
    const alert = await makeAlert();
    const patch = (body: object) =>
      request(app).patch(`/api/v1/alerts/${alert.id}`).set(auth(token)).send(body);

    const ack = await patch({ status: 'ACKNOWLEDGED' });
    expect(ack.body.alert).toMatchObject({ status: 'ACKNOWLEDGED', acknowledgedById: me.id });
    const resolved = await patch({ status: 'RESOLVED' });
    expect(resolved.body.alert).toMatchObject({ status: 'RESOLVED', resolvedById: me.id });
    expect(
      await prisma.auditLog.count({
        where: { action: { in: ['alert.acknowledged', 'alert.resolved'] } },
      }),
    ).toBe(2);
  });

  it('rejects invalid transitions', async () => {
    const token = await tokenFor('a@example.com', 'ANALYST');
    const resolved = await makeAlert({ status: 'RESOLVED', resolvedAt: new Date() });
    const acked = await makeAlert({ groupKey: '9.9.9.9', status: 'ACKNOWLEDGED' });
    const patch = (id: string, body: object) =>
      request(app).patch(`/api/v1/alerts/${id}`).set(auth(token)).send(body);
    expect((await patch(resolved.id, { status: 'ACKNOWLEDGED' })).body.error.code).toBe(
      'INVALID_TRANSITION',
    );
    expect((await patch(resolved.id, { status: 'RESOLVED' })).status).toBe(409);
    expect((await patch(acked.id, { status: 'ACKNOWLEDGED' })).status).toBe(409);
    expect((await patch(acked.id, { status: 'OPEN' })).status).toBe(400); // OPEN is not even an allowed input
  });

  it('assigns to analysts/admins only, and can unassign', async () => {
    const token = await tokenFor('a@example.com', 'ANALYST');
    const viewer = await createUser('v@example.com', 'VIEWER');
    const colleague = await createUser('c@example.com', 'ANALYST');
    const inactive = await createUser('i@example.com', 'ANALYST');
    await prisma.user.update({ where: { id: inactive.id }, data: { isActive: false } });
    const alert = await makeAlert();
    const patch = (body: object) =>
      request(app).patch(`/api/v1/alerts/${alert.id}`).set(auth(token)).send(body);

    expect((await patch({ assigneeId: viewer.id })).status).toBe(400);
    expect((await patch({ assigneeId: inactive.id })).status).toBe(400);
    expect((await patch({ assigneeId: '00000000-0000-4000-8000-000000000000' })).status).toBe(400);
    expect((await patch({ assigneeId: colleague.id })).body.alert.assigneeId).toBe(colleague.id);
    expect((await patch({ assigneeId: null })).body.alert.assigneeId).toBeNull();
  });

  it('validates the body', async () => {
    const token = await tokenFor('a@example.com', 'ANALYST');
    const alert = await makeAlert();
    const patch = (body: object) =>
      request(app).patch(`/api/v1/alerts/${alert.id}`).set(auth(token)).send(body);
    expect((await patch({})).status).toBe(400);
    expect((await patch({ title: 'hacked' })).status).toBe(400);
    expect((await patch({ severity: 'LOW' })).status).toBe(400);
  });
});

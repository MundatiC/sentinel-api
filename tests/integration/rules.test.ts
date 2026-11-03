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
const rule = (overrides: Record<string, unknown> = {}) => ({
  name: 'Too many 404s',
  eventType: 'http.not_found',
  groupBy: 'IP',
  threshold: 20,
  windowSeconds: 60,
  severity: 'MEDIUM',
  ...overrides,
});

describe('alert rules API', () => {
  it('lets any logged-in user list rules but only admins change them', async () => {
    const viewer = await tokenFor('v@example.com', 'VIEWER');
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    expect((await request(app).get('/api/v1/alert-rules').set(auth(viewer))).status).toBe(200);
    expect(
      (await request(app).post('/api/v1/alert-rules').set(auth(analyst)).send(rule())).status,
    ).toBe(403);
    expect((await request(app).post('/api/v1/alert-rules').send(rule())).status).toBe(401);
  });

  it('creates, updates and audits', async () => {
    const admin = await tokenFor('admin@example.com', 'ADMIN');
    const created = await request(app).post('/api/v1/alert-rules').set(auth(admin)).send(rule());
    expect(created.status).toBe(201);
    expect(created.body.rule).toMatchObject({ enabled: true, cooldownSeconds: 300, threshold: 20 });

    const updated = await request(app)
      .patch(`/api/v1/alert-rules/${created.body.rule.id}`)
      .set(auth(admin))
      .send({ enabled: false, threshold: 50 });
    expect(updated.body.rule).toMatchObject({ enabled: false, threshold: 50 });
    expect(await prisma.auditLog.count({ where: { action: { startsWith: 'alert_rule.' } } })).toBe(
      2,
    );
  });

  it('rejects duplicate names with 409 and unknown ids with 404', async () => {
    const admin = await tokenFor('admin@example.com', 'ADMIN');
    await request(app).post('/api/v1/alert-rules').set(auth(admin)).send(rule());
    expect(
      (await request(app).post('/api/v1/alert-rules').set(auth(admin)).send(rule())).body.error
        .code,
    ).toBe('RULE_NAME_TAKEN');
    expect(
      (
        await request(app)
          .patch('/api/v1/alert-rules/00000000-0000-4000-8000-000000000000')
          .set(auth(admin))
          .send({ enabled: false })
      ).status,
    ).toBe(404);
  });

  it.each([
    ['zero threshold', { threshold: 0 }],
    ['huge window', { windowSeconds: 10_000_000 }],
    ['bad severity', { severity: 'MEGA' }],
    ['bad event type', { eventType: 'Not Valid!' }],
    ['unknown field', { createdById: 'x' }],
  ])('validates: %s', async (_name, override) => {
    const admin = await tokenFor('admin@example.com', 'ADMIN');
    expect(
      (await request(app).post('/api/v1/alert-rules').set(auth(admin)).send(rule(override))).status,
    ).toBe(400);
  });

  it('deletes unused rules but refuses to delete a rule that has alerts', async () => {
    const admin = await tokenFor('admin@example.com', 'ADMIN');
    const unused = (await request(app).post('/api/v1/alert-rules').set(auth(admin)).send(rule()))
      .body.rule;
    expect(
      (await request(app).delete(`/api/v1/alert-rules/${unused.id}`).set(auth(admin))).status,
    ).toBe(204);

    const used = (
      await request(app)
        .post('/api/v1/alert-rules')
        .set(auth(admin))
        .send(rule({ name: 'used' }))
    ).body.rule;
    await prisma.alert.create({
      data: {
        ruleId: used.id,
        title: 't',
        groupKey: 'k',
        severity: 'LOW',
        firstEventAt: new Date(),
        lastEventAt: new Date(),
      },
    });
    const res = await request(app).delete(`/api/v1/alert-rules/${used.id}`).set(auth(admin));
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('RULE_IN_USE');
  });
});

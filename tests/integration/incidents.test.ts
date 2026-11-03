import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createApiKey, createUser, loginAs, resetDb } from '../helpers.js';

const { app } = buildTestApp();
beforeEach(resetDb);

async function tokenFor(email: string, role: 'ADMIN' | 'ANALYST' | 'VIEWER') {
  await createUser(email, role);
  return (await loginAs(app, email)).accessToken;
}
const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

async function makeAlert(groupKey = '1.1.1.1') {
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
  return prisma.alert.create({
    data: {
      ruleId: rule.id,
      title: `Brute force: ${groupKey}`,
      groupKey,
      severity: 'HIGH',
      firstEventAt: new Date(),
      lastEventAt: new Date(),
    },
  });
}

describe('incident access control', () => {
  it('viewers can read but not write', async () => {
    const viewer = await tokenFor('v@example.com', 'VIEWER');
    expect((await request(app).get('/api/v1/incidents').set(auth(viewer))).status).toBe(200);
    expect(
      (
        await request(app)
          .post('/api/v1/incidents')
          .set(auth(viewer))
          .send({ title: 't', severity: 'LOW' })
      ).status,
    ).toBe(403);
    expect((await request(app).get('/api/v1/incidents')).status).toBe(401);
  });
});

describe('creating incidents', () => {
  it('creates an incident with an opening timeline entry and linked alerts', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const alert = await makeAlert();
    const res = await request(app)
      .post('/api/v1/incidents')
      .set(auth(analyst))
      .send({
        title: 'Brute force on login',
        severity: 'HIGH',
        summary: 'Investigating',
        alertIds: [alert.id],
      });
    expect(res.status).toBe(201);
    const { incident } = res.body;
    expect(incident).toMatchObject({
      title: 'Brute force on login',
      status: 'OPEN',
      severity: 'HIGH',
    });
    expect(incident.timeline.map((e: { kind: string }) => e.kind)).toEqual([
      'STATUS_CHANGE',
      'ALERT_LINKED',
    ]);
    expect(incident.timeline[0].author.email).toBe('a@example.com');
    expect(incident.alerts).toHaveLength(1);
    expect(incident.alerts[0]).toMatchObject({ id: alert.id, ruleName: 'rule' });
  });

  it('is all-or-nothing: an unknown alert id means no incident is created', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const res = await request(app)
      .post('/api/v1/incidents')
      .set(auth(analyst))
      .send({ title: 't', severity: 'LOW', alertIds: ['00000000-0000-4000-8000-000000000000'] });
    expect(res.status).toBe(400);
    expect(await prisma.incident.count()).toBe(0);
  });

  it('refuses to steal an alert that belongs to another incident', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const alert = await makeAlert();
    const create = () =>
      request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 't', severity: 'LOW', alertIds: [alert.id] });
    expect((await create()).status).toBe(201);
    const second = await create();
    expect(second.status).toBe(409);
    expect(second.body.error.code).toBe('ALERT_ALREADY_LINKED');
    expect(await prisma.incident.count()).toBe(1);
  });

  it('validates input', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const post = (body: object) =>
      request(app).post('/api/v1/incidents').set(auth(analyst)).send(body);
    expect((await post({ title: '', severity: 'LOW' })).status).toBe(400);
    expect((await post({ title: 't', severity: 'SCARY' })).status).toBe(400);
    expect((await post({ title: 't', severity: 'LOW', status: 'RESOLVED' })).status).toBe(400);
    expect((await post({ title: 't', severity: 'LOW', alertIds: ['nope'] })).status).toBe(400);
  });
});

describe('updating incidents', () => {
  async function newIncident(token: string) {
    return (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(token))
        .send({ title: 'Inc', severity: 'MEDIUM' })
    ).body.incident;
  }

  it('records status changes in the timeline and sets/clears resolvedAt', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = await newIncident(analyst);
    const patch = (body: object) =>
      request(app).patch(`/api/v1/incidents/${incident.id}`).set(auth(analyst)).send(body);

    const investigating = await patch({ status: 'INVESTIGATING' });
    expect(investigating.body.incident.status).toBe('INVESTIGATING');
    const resolved = await patch({ status: 'RESOLVED' });
    expect(resolved.body.incident.resolvedAt).not.toBeNull();
    const reopened = await patch({ status: 'OPEN' });
    expect(reopened.body.incident.resolvedAt).toBeNull();

    const bodies = reopened.body.incident.timeline.map((e: { body: string }) => e.body);
    expect(bodies).toContain('Status changed from OPEN to INVESTIGATING');
    expect(bodies).toContain('Status changed from RESOLVED to OPEN');
    expect(await prisma.auditLog.count({ where: { action: 'incident.status_changed' } })).toBe(3);
  });

  it('changing the title does not add a status entry', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = await newIncident(analyst);
    const res = await request(app)
      .patch(`/api/v1/incidents/${incident.id}`)
      .set(auth(analyst))
      .send({ title: 'Renamed', summary: 'More detail' });
    expect(res.body.incident).toMatchObject({ title: 'Renamed', summary: 'More detail' });
    expect(res.body.incident.timeline).toHaveLength(1);
  });

  it('validates and 404s', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = await newIncident(analyst);
    const patch = (id: string, body: object) =>
      request(app).patch(`/api/v1/incidents/${id}`).set(auth(analyst)).send(body);
    expect((await patch(incident.id, {})).status).toBe(400);
    expect((await patch(incident.id, { status: 'DONE' })).status).toBe(400);
    expect((await patch(incident.id, { createdById: 'x' })).status).toBe(400);
    expect((await patch('00000000-0000-4000-8000-000000000000', { title: 'x' })).status).toBe(404);
  });
});

describe('timeline notes and alert links', () => {
  it('adds notes, optionally back-dated, but never future-dated', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 'Inc', severity: 'LOW' })
    ).body.incident;
    const note = (body: object) =>
      request(app).post(`/api/v1/incidents/${incident.id}/timeline`).set(auth(analyst)).send(body);

    expect(
      (await note({ body: 'Blocked the IP at the firewall', occurredAt: '2020-01-01T00:00:00Z' }))
        .status,
    ).toBe(201);
    expect(
      (await note({ body: 'x', occurredAt: new Date(Date.now() + 3_600_000).toISOString() }))
        .status,
    ).toBe(400);
    expect((await note({ body: '   ' })).status).toBe(400);

    const detail = await request(app).get(`/api/v1/incidents/${incident.id}`).set(auth(analyst));
    // timeline is chronological: the back-dated note comes first
    expect(detail.body.incident.timeline[0].body).toBe('Blocked the IP at the firewall');
  });

  it('stores hostile note text verbatim (the UI is responsible for escaping)', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 'Inc', severity: 'LOW' })
    ).body.incident;
    const text = '<img src=x onerror=alert(1)>';
    const res = await request(app)
      .post(`/api/v1/incidents/${incident.id}/timeline`)
      .set(auth(analyst))
      .send({ body: text });
    expect(res.body.entry.body).toBe(text);
    expect(res.headers['content-type']).toContain('application/json'); // never HTML
  });

  it('links an alert later; linking again is a harmless no-op', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 'Inc', severity: 'LOW' })
    ).body.incident;
    const alert = await makeAlert();
    const link = () =>
      request(app)
        .post(`/api/v1/incidents/${incident.id}/alerts`)
        .set(auth(analyst))
        .send({ alertId: alert.id });
    expect((await link()).status).toBe(201);
    const again = await link();
    expect(again.status).toBe(200);
    expect(
      again.body.incident.timeline.filter((e: { kind: string }) => e.kind === 'ALERT_LINKED'),
    ).toHaveLength(1);
  });
});

describe('listing incidents', () => {
  it('filters by status and shows alert counts', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const alert = await makeAlert();
    await request(app)
      .post('/api/v1/incidents')
      .set(auth(analyst))
      .send({ title: 'One', severity: 'HIGH', alertIds: [alert.id] });
    const two = (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 'Two', severity: 'LOW' })
    ).body.incident;
    await request(app)
      .patch(`/api/v1/incidents/${two.id}`)
      .set(auth(analyst))
      .send({ status: 'RESOLVED' });

    const all = await request(app).get('/api/v1/incidents').set(auth(analyst));
    expect(all.body.pagination.total).toBe(2);
    expect(all.body.data.find((i: { title: string }) => i.title === 'One').alertCount).toBe(1);
    expect(
      (await request(app).get('/api/v1/incidents?status=RESOLVED').set(auth(analyst))).body.data,
    ).toHaveLength(1);
    expect(
      (await request(app).get('/api/v1/incidents?severity=bogus').set(auth(analyst))).status,
    ).toBe(400);
  });
});

describe('GET /export/incidents/:id (API key, for the scanner)', () => {
  it('needs the incidents:read scope', async () => {
    const analyst = await tokenFor('a@example.com', 'ANALYST');
    const incident = (
      await request(app)
        .post('/api/v1/incidents')
        .set(auth(analyst))
        .send({ title: 'Inc', severity: 'LOW' })
    ).body.incident;
    const writeOnly = await createApiKey(['events:write']);
    const reader = await createApiKey(['incidents:read']);

    expect((await request(app).get(`/api/v1/export/incidents/${incident.id}`)).status).toBe(401);
    expect(
      (
        await request(app)
          .get(`/api/v1/export/incidents/${incident.id}`)
          .set('X-API-Key', writeOnly.raw)
      ).status,
    ).toBe(403);
    const ok = await request(app)
      .get(`/api/v1/export/incidents/${incident.id}`)
      .set('X-API-Key', reader.raw);
    expect(ok.status).toBe(200);
    expect(ok.body.incident.timeline).toHaveLength(1);
  });
});

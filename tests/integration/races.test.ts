import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createUser, loginAs, resetDb, TEST_PASSWORD } from '../helpers.js';

const { app } = buildTestApp({ ALLOW_REGISTRATION: 'true' });
beforeEach(resetDb);

describe('concurrent requests (check-then-write races)', () => {
  it('two simultaneous registrations of one email: one 201, one 409, never a 500', async () => {
    const send = () =>
      request(app)
        .post('/api/v1/auth/register')
        .send({ email: 'same@example.com', password: TEST_PASSWORD });
    const statuses = (await Promise.all([send(), send(), send()])).map((r) => r.status).sort();
    expect(statuses).toEqual([201, 409, 409]);
    expect(await prisma.user.count()).toBe(1);
  });

  it('an alert that was resolved cannot be moved back to acknowledged by a racing request', async () => {
    await createUser('a@example.com', 'ANALYST');
    const { accessToken } = await loginAs(app, 'a@example.com');
    const rule = await prisma.alertRule.create({
      data: { name: 'r', eventType: 'x.y', threshold: 1, windowSeconds: 60, severity: 'HIGH' },
    });
    for (let round = 0; round < 15; round++) {
      const alert = await prisma.alert.create({
        data: {
          ruleId: rule.id,
          title: `t${round}`,
          groupKey: `k${round}`,
          severity: 'HIGH',
          firstEventAt: new Date(),
          lastEventAt: new Date(),
        },
      });
      const patch = (status: string) =>
        request(app)
          .patch(`/api/v1/alerts/${alert.id}`)
          .set('Authorization', `Bearer ${accessToken}`)
          .send({ status });
      await Promise.all([patch('ACKNOWLEDGED'), patch('RESOLVED')]);
      const final = await prisma.alert.findUniqueOrThrow({ where: { id: alert.id } });
      // the invariant: once resolvedAt is set the status must be RESOLVED
      if (final.resolvedAt) expect(final.status).toBe('RESOLVED');
    }
  });

  it('an alert can only join one incident even when two analysts link it at the same moment', async () => {
    await createUser('a@example.com', 'ANALYST');
    const { accessToken } = await loginAs(app, 'a@example.com');
    const auth = { Authorization: `Bearer ${accessToken}` };
    const rule = await prisma.alertRule.create({
      data: { name: 'r', eventType: 'x.y', threshold: 1, windowSeconds: 60, severity: 'HIGH' },
    });
    const alert = await prisma.alert.create({
      data: {
        ruleId: rule.id,
        title: 't',
        groupKey: 'k',
        severity: 'HIGH',
        firstEventAt: new Date(),
        lastEventAt: new Date(),
      },
    });
    const make = async (title: string) =>
      (await request(app).post('/api/v1/incidents').set(auth).send({ title, severity: 'LOW' })).body
        .incident.id as string;
    const [one, two] = [await make('one'), await make('two')];
    const link = (id: string) =>
      request(app).post(`/api/v1/incidents/${id}/alerts`).set(auth).send({ alertId: alert.id });
    const results = await Promise.all([link(one), link(two)]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    const entries = await prisma.incidentTimelineEntry.count({ where: { kind: 'ALERT_LINKED' } });
    expect(entries).toBe(1); // no incident may claim an alert that another incident already owns
  });
});

describe('refresh token housekeeping', () => {
  it('expired and long-revoked refresh tokens are removed when someone logs in', async () => {
    const user = await createUser('u@example.com');
    const old = new Date(Date.now() - 40 * 86_400_000);
    await prisma.refreshToken.createMany({
      data: [
        { userId: user.id, tokenHash: 'expired-1', familyId: user.id, expiresAt: old },
        {
          userId: user.id,
          tokenHash: 'revoked-1',
          familyId: user.id,
          expiresAt: new Date(Date.now() + 86_400_000),
          revokedAt: old,
        },
      ],
    });
    await loginAs(app, 'u@example.com');
    const left = await prisma.refreshToken.findMany({ select: { tokenHash: true } });
    expect(left.map((t) => t.tokenHash)).not.toContain('expired-1');
    expect(left.map((t) => t.tokenHash)).not.toContain('revoked-1');
    expect(left).toHaveLength(1); // only the new login's token remains
  });
});

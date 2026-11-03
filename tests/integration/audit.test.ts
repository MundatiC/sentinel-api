import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, createUser, loginAs, resetDb } from '../helpers.js';

const { app } = buildTestApp();
beforeEach(resetDb);

describe('GET /audit-logs', () => {
  it('is admin only', async () => {
    await createUser('a@example.com', 'ANALYST');
    const { accessToken } = await loginAs(app, 'a@example.com');
    expect(
      (await request(app).get('/api/v1/audit-logs').set('Authorization', `Bearer ${accessToken}`))
        .status,
    ).toBe(403);
    expect((await request(app).get('/api/v1/audit-logs')).status).toBe(401);
  });

  it('lists entries newest first, filterable by action prefix and actor, with string ids', async () => {
    await createUser('admin@example.com', 'ADMIN');
    const admin = await loginAs(app, 'admin@example.com');
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'nobody@example.com', password: 'wrong-wrong-wrong' });
    const auth = { Authorization: `Bearer ${admin.accessToken}` };

    const all = await request(app).get('/api/v1/audit-logs').set(auth);
    expect(all.status).toBe(200);
    expect(typeof all.body.data[0].id).toBe('string');
    expect(all.body.data[0].action).toBe('auth.login_failed');
    expect(all.body.pagination.total).toBe(2);

    const failed = await request(app).get('/api/v1/audit-logs?action=auth.login_f').set(auth);
    expect(failed.body.pagination.total).toBe(1);
    const mine = await request(app)
      .get(`/api/v1/audit-logs?actorId=${all.body.data[1].actorId}`)
      .set(auth);
    expect(
      mine.body.data.every((row: { actorId: string }) => row.actorId === all.body.data[1].actorId),
    ).toBe(true);
    expect((await request(app).get('/api/v1/audit-logs?actorId=nope').set(auth)).status).toBe(400);
  });
});

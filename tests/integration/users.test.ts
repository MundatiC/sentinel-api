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

describe('access control on /users', () => {
  it('401 without a token', async () => {
    expect((await request(app).get('/api/v1/users')).status).toBe(401);
  });

  it.each(['VIEWER', 'ANALYST'] as const)('403 for %s', async (role) => {
    const token = await tokenFor('u@example.com', role);
    expect(
      (await request(app).get('/api/v1/users').set('Authorization', `Bearer ${token}`)).status,
    ).toBe(403);
  });
});

describe('GET /users', () => {
  it('lists users with pagination and never exposes password hashes', async () => {
    const token = await tokenFor('admin@example.com', 'ADMIN');
    await createUser('b@example.com');
    await createUser('c@example.com');
    const res = await request(app)
      .get('/api/v1/users?page=1&pageSize=2')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(2);
    expect(res.body.pagination).toEqual({ page: 1, pageSize: 2, total: 3, totalPages: 2 });
    expect(JSON.stringify(res.body)).not.toContain('passwordHash');
  });

  it('rejects an oversized page size', async () => {
    const token = await tokenFor('admin@example.com', 'ADMIN');
    expect(
      (
        await request(app)
          .get('/api/v1/users?pageSize=100000')
          .set('Authorization', `Bearer ${token}`)
      ).status,
    ).toBe(400);
  });
});

describe('PATCH /users/:id', () => {
  it('changes a role and writes an audit entry', async () => {
    const token = await tokenFor('admin@example.com', 'ADMIN');
    const target = await createUser('t@example.com');
    const res = await request(app)
      .patch(`/api/v1/users/${target.id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'ANALYST' });
    expect(res.status).toBe(200);
    expect(res.body.user.role).toBe('ANALYST');
    const log = await prisma.auditLog.findFirstOrThrow({ where: { action: 'user.role_changed' } });
    expect(log.targetId).toBe(target.id);
    expect(log.metadata).toMatchObject({ from: { role: 'VIEWER' }, to: { role: 'ANALYST' } });
  });

  it('role changes take effect immediately on existing tokens', async () => {
    const adminToken = await tokenFor('admin@example.com', 'ADMIN');
    const target = await createUser('t@example.com', 'ADMIN');
    const { accessToken: targetToken } = await loginAs(app, 't@example.com');
    expect(
      (await request(app).get('/api/v1/users').set('Authorization', `Bearer ${targetToken}`))
        .status,
    ).toBe(200);
    await request(app)
      .patch(`/api/v1/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'VIEWER' });
    expect(
      (await request(app).get('/api/v1/users').set('Authorization', `Bearer ${targetToken}`))
        .status,
    ).toBe(403);
  });

  it('refuses to let an admin change their own role', async () => {
    await createUser('admin@example.com', 'ADMIN');
    const { accessToken } = await loginAs(app, 'admin@example.com');
    const me = await prisma.user.findFirstOrThrow({ where: { email: 'admin@example.com' } });
    const res = await request(app)
      .patch(`/api/v1/users/${me.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ role: 'VIEWER' });
    expect(res.status).toBe(400);
  });

  it('deactivating a user ends their sessions', async () => {
    const adminToken = await tokenFor('admin@example.com', 'ADMIN');
    const target = await createUser('t@example.com');
    const { cookie } = await loginAs(app, 't@example.com');
    await request(app)
      .patch(`/api/v1/users/${target.id}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ isActive: false });
    expect((await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie)).status).toBe(
      401,
    );
  });

  it('validates input: unknown fields, bad role, bad id, empty body', async () => {
    const token = await tokenFor('admin@example.com', 'ADMIN');
    const target = await createUser('t@example.com');
    const patch = (id: string, body: object) =>
      request(app).patch(`/api/v1/users/${id}`).set('Authorization', `Bearer ${token}`).send(body);
    expect((await patch(target.id, { passwordHash: 'x' })).status).toBe(400);
    expect((await patch(target.id, { role: 'SUPERUSER' })).status).toBe(400);
    expect((await patch('not-a-uuid', { role: 'VIEWER' })).status).toBe(400);
    expect((await patch(target.id, {})).status).toBe(400);
    expect((await patch('00000000-0000-4000-8000-000000000000', { role: 'VIEWER' })).status).toBe(
      404,
    );
  });
});

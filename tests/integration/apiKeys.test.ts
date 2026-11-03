import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { sha256 } from '../../src/lib/crypto.js';
import {
  buildTestApp,
  createApiKey,
  createUser,
  loginAs,
  resetDb,
  sampleEvent,
} from '../helpers.js';

const { app } = buildTestApp();

beforeEach(resetDb);

async function adminToken() {
  await createUser('admin@example.com', 'ADMIN');
  return (await loginAs(app, 'admin@example.com')).accessToken;
}

describe('API key management', () => {
  it('is admin only', async () => {
    await createUser('analyst@example.com', 'ANALYST');
    const { accessToken } = await loginAs(app, 'analyst@example.com');
    expect(
      (await request(app).get('/api/v1/api-keys').set('Authorization', `Bearer ${accessToken}`))
        .status,
    ).toBe(403);
    expect((await request(app).post('/api/v1/api-keys').send({})).status).toBe(401);
  });

  it('shows the raw key once and stores only its hash', async () => {
    const token = await adminToken();
    const res = await request(app)
      .post('/api/v1/api-keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'scanner', scopes: ['scans:write'] });
    expect(res.status).toBe(201);
    expect(res.body.key).toMatch(/^snt_/);

    const stored = await prisma.apiKey.findFirstOrThrow();
    expect(stored.keyHash).toBe(sha256(res.body.key));
    expect(JSON.stringify(stored)).not.toContain(res.body.key);

    const list = await request(app).get('/api/v1/api-keys').set('Authorization', `Bearer ${token}`);
    expect(JSON.stringify(list.body)).not.toContain(res.body.key);
    expect(JSON.stringify(list.body)).not.toContain('keyHash');
    expect(list.body.data[0]).toMatchObject({ name: 'scanner', prefix: stored.prefix });
  });

  it('audits creation without recording the key', async () => {
    const token = await adminToken();
    const res = await request(app)
      .post('/api/v1/api-keys')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: 'k', scopes: ['events:write'] });
    const log = await prisma.auditLog.findFirstOrThrow({ where: { action: 'api_key.created' } });
    expect(JSON.stringify(log.metadata)).not.toContain(res.body.key);
  });

  it('validates the body', async () => {
    const token = await adminToken();
    const post = (body: object) =>
      request(app).post('/api/v1/api-keys').set('Authorization', `Bearer ${token}`).send(body);
    expect((await post({ name: '', scopes: ['events:write'] })).status).toBe(400);
    expect((await post({ name: 'x', scopes: [] })).status).toBe(400);
    expect((await post({ name: 'x', scopes: ['admin:everything'] })).status).toBe(400);
    expect(
      (await post({ name: 'x', scopes: ['events:write'], expiresAt: '2000-01-01T00:00:00Z' }))
        .status,
    ).toBe(400);
  });

  it('revoking a key stops it working immediately', async () => {
    const token = await adminToken();
    const { raw, key } = await createApiKey();
    const ok = () =>
      request(app)
        .post('/api/v1/ingest/events')
        .set('X-API-Key', raw)
        .send({ events: [sampleEvent()] });
    expect((await ok()).status).toBe(201);

    expect(
      (
        await request(app)
          .delete(`/api/v1/api-keys/${key.id}`)
          .set('Authorization', `Bearer ${token}`)
      ).status,
    ).toBe(204);
    expect((await ok()).status).toBe(401);
    // revoking twice is harmless and does not create a second audit entry
    expect(
      (
        await request(app)
          .delete(`/api/v1/api-keys/${key.id}`)
          .set('Authorization', `Bearer ${token}`)
      ).status,
    ).toBe(204);
    expect(await prisma.auditLog.count({ where: { action: 'api_key.revoked' } })).toBe(1);
  });
});

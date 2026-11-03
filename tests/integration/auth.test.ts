import jwt from 'jsonwebtoken';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { sha256 } from '../../src/lib/crypto.js';
import { buildTestApp, createUser, loginAs, resetDb, TEST_PASSWORD } from '../helpers.js';

const { app, env } = buildTestApp();
const cookieName = 'sentinel_refresh';

beforeEach(resetDb);

describe('POST /auth/register', () => {
  it('is disabled by default', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'a@example.com', password: TEST_PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('REGISTRATION_DISABLED');
  });

  it('creates a VIEWER when enabled and lowercases the email', async () => {
    const { app: open } = buildTestApp({ ALLOW_REGISTRATION: 'true' });
    const res = await request(open)
      .post('/api/v1/auth/register')
      .send({ email: 'New@Example.com', password: TEST_PASSWORD });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ email: 'new@example.com', role: 'VIEWER' });
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  it('refuses to let a client choose its own role (mass assignment)', async () => {
    const { app: open } = buildTestApp({ ALLOW_REGISTRATION: 'true' });
    const res = await request(open)
      .post('/api/v1/auth/register')
      .send({ email: 'evil@example.com', password: TEST_PASSWORD, role: 'ADMIN' });
    expect(res.status).toBe(400);
    expect(await prisma.user.count()).toBe(0);
  });

  it('rejects short passwords', async () => {
    const { app: open } = buildTestApp({ ALLOW_REGISTRATION: 'true' });
    const res = await request(open)
      .post('/api/v1/auth/register')
      .send({ email: 'a@example.com', password: 'short' });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('VALIDATION_ERROR');
  });
});

describe('POST /auth/login', () => {
  it('returns an access token and sets a hardened refresh cookie', async () => {
    await createUser('user@example.com');
    const { res } = await loginAs(app, 'user@example.com');
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    expect(res.body.user.email).toBe('user@example.com');
    expect(res.body.refreshToken).toBeUndefined(); // the refresh token only travels in the cookie

    const setCookie = (res.headers['set-cookie'] as unknown as string[])[0]!;
    expect(setCookie).toContain(`${cookieName}=`);
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Strict');
    expect(setCookie).toContain('Path=/api/v1/auth');
  });

  it('stores only a hash of the refresh token', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    const raw = cookie.split('=')[1]!;
    const stored = await prisma.refreshToken.findFirstOrThrow();
    expect(stored.tokenHash).toBe(sha256(raw));
    expect(stored.tokenHash).not.toBe(raw);
  });

  it('gives the same generic error for wrong password and unknown email', async () => {
    await createUser('user@example.com');
    const wrong = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', password: 'nope-nope-nope' });
    const unknown = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ghost@example.com', password: 'nope-nope-nope' });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.error.message).toBe(unknown.body.error.message);
    expect(wrong.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('rejects inactive users with the same generic error', async () => {
    const user = await createUser('user@example.com');
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });
    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'user@example.com', password: TEST_PASSWORD });
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('INVALID_CREDENTIALS');
  });

  it('audits failures without ever recording the password', async () => {
    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: 'ghost@example.com', password: 'super-secret-guess' });
    const log = await prisma.auditLog.findFirstOrThrow({ where: { action: 'auth.login_failed' } });
    expect(JSON.stringify(log.metadata)).not.toContain('super-secret-guess');
    expect(log.metadata).toMatchObject({ email: 'ghost@example.com', reason: 'unknown_user' });
  });

  it('rate limits repeated attempts for the same email', async () => {
    const { app: strict } = buildTestApp({ LOGIN_RATE_LIMIT: '3' });
    const attempt = () =>
      request(strict)
        .post('/api/v1/auth/login')
        .send({ email: 'x@example.com', password: 'wrong-wrong-wrong' });
    for (let i = 0; i < 3; i++) expect((await attempt()).status).toBe(401);
    const blocked = await attempt();
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('RATE_LIMITED');
  });
});

describe('GET /auth/me and token verification', () => {
  it('requires a token', async () => {
    expect((await request(app).get('/api/v1/auth/me')).status).toBe(401);
  });

  it('returns the current user', async () => {
    await createUser('user@example.com', 'ANALYST');
    const { accessToken } = await loginAs(app, 'user@example.com');
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ email: 'user@example.com', role: 'ANALYST' });
  });

  it('rejects a token signed with the wrong secret', async () => {
    const user = await createUser('user@example.com');
    const forged = jwt.sign({ role: 'ADMIN' }, 'attacker-secret-attacker-secret-1234', {
      subject: user.id,
      issuer: 'sentinel-api',
    });
    const res = await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${forged}`);
    expect(res.status).toBe(401);
  });

  it('rejects an unsigned token (alg none)', async () => {
    const user = await createUser('user@example.com');
    const unsigned = jwt.sign({ role: 'ADMIN' }, '', {
      subject: user.id,
      issuer: 'sentinel-api',
      algorithm: 'none',
    });
    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${unsigned}`);
    expect(res.status).toBe(401);
  });

  it('rejects an expired token', async () => {
    const user = await createUser('user@example.com');
    const expired = jwt.sign({ role: 'VIEWER' }, env.JWT_ACCESS_SECRET, {
      subject: user.id,
      issuer: 'sentinel-api',
      expiresIn: -10,
    });
    expect(
      (await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${expired}`)).status,
    ).toBe(401);
  });

  it('stops working immediately when the user is deactivated', async () => {
    const user = await createUser('user@example.com');
    const { accessToken } = await loginAs(app, 'user@example.com');
    await prisma.user.update({ where: { id: user.id }, data: { isActive: false } });
    expect(
      (await request(app).get('/api/v1/auth/me').set('Authorization', `Bearer ${accessToken}`))
        .status,
    ).toBe(401);
  });
});

describe('POST /auth/refresh', () => {
  it('rotates the refresh token and returns a new access token', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    const res = await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie);
    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeTruthy();
    const newCookie = (res.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
    expect(newCookie).not.toBe(cookie);

    const tokens = await prisma.refreshToken.findMany({ orderBy: { createdAt: 'asc' } });
    expect(tokens).toHaveLength(2);
    expect(tokens[0]!.revokedAt).not.toBeNull();
    expect(tokens[0]!.replacedById).toBe(tokens[1]!.id);
    expect(tokens[0]!.familyId).toBe(tokens[1]!.familyId);
  });

  it('requires the cookie', async () => {
    expect((await request(app).post('/api/v1/auth/refresh')).status).toBe(401);
  });

  it('revokes the whole family when an old token is replayed (theft detection)', async () => {
    await createUser('user@example.com');
    const { cookie: stolen } = await loginAs(app, 'user@example.com');
    const rotated = await request(app).post('/api/v1/auth/refresh').set('Cookie', stolen);
    const legit = (rotated.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;

    // Pretend the rotation happened a minute ago, so the replay is not mistaken for a tab race.
    await prisma.refreshToken.updateMany({
      where: { revokedAt: { not: null } },
      data: { revokedAt: new Date(Date.now() - 60_000) },
    });

    const replay = await request(app).post('/api/v1/auth/refresh').set('Cookie', stolen);
    expect(replay.status).toBe(401);

    // The victim's newest token is dead too: everyone must log in again.
    const victim = await request(app).post('/api/v1/auth/refresh').set('Cookie', legit);
    expect(victim.status).toBe(401);
    expect(await prisma.auditLog.count({ where: { action: 'auth.refresh_reuse_detected' } })).toBe(
      1,
    );
  });

  it('does not revoke the family when the replay comes right after a rotation (tab race)', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    const first = await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie);
    const second = await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie);
    expect(second.status).toBe(401);
    const winner = (first.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
    expect((await request(app).post('/api/v1/auth/refresh').set('Cookie', winner)).status).toBe(
      200,
    );
  });

  it('rejects expired refresh tokens', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    await prisma.refreshToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    expect((await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie)).status).toBe(
      401,
    );
  });

  it('lets only one of two concurrent refreshes win', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    const results = await Promise.all([
      request(app).post('/api/v1/auth/refresh').set('Cookie', cookie),
      request(app).post('/api/v1/auth/refresh').set('Cookie', cookie),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });
});

describe('POST /auth/logout', () => {
  it('revokes the session and clears the cookie', async () => {
    await createUser('user@example.com');
    const { cookie } = await loginAs(app, 'user@example.com');
    const out = await request(app).post('/api/v1/auth/logout').set('Cookie', cookie);
    expect(out.status).toBe(204);
    expect((out.headers['set-cookie'] as unknown as string[])[0]).toContain(`${cookieName}=;`);
    expect((await request(app).post('/api/v1/auth/refresh').set('Cookie', cookie)).status).toBe(
      401,
    );
  });
});

import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { buildTestApp, createUser, resetDb, TEST_PASSWORD } from '../helpers.js';

// TRUST_PROXY=1 so X-Forwarded-For stands in for "different visitors". The per-IP+email limit is set very high:
// these tests are about the per-ACCOUNT limit only.
const { app } = buildTestApp({ TRUST_PROXY: '1', ACCOUNT_LOGIN_RATE_LIMIT: '3' });

beforeEach(resetDb);

const login = (email: string, ip: string, password = 'wrong-wrong-wrong') =>
  request(app).post('/api/v1/auth/login').set('X-Forwarded-For', ip).send({ email, password });

describe('per-account login limit', () => {
  it('blocks failed guesses against one account even when the IP keeps changing', async () => {
    await createUser('victim@example.com');
    for (const ip of ['198.51.100.1', '198.51.100.2', '198.51.100.3']) {
      expect((await login('victim@example.com', ip)).status).toBe(401);
    }
    const blocked = await login('victim@example.com', '198.51.100.4', TEST_PASSWORD);
    expect(blocked.status).toBe(429);
    expect(blocked.body.error.code).toBe('RATE_LIMITED');
  });

  it('does not lock the owner out from an IP that already logged in successfully', async () => {
    await createUser('owner@example.com');
    expect((await login('owner@example.com', '203.0.113.10', TEST_PASSWORD)).status).toBe(200);

    for (const ip of ['198.51.100.1', '198.51.100.2', '198.51.100.3'])
      await login('owner@example.com', ip);
    expect((await login('owner@example.com', '198.51.100.4', TEST_PASSWORD)).status).toBe(429); // attacker

    const owner = await login('owner@example.com', '203.0.113.10', TEST_PASSWORD);
    expect(owner.status).toBe(200); // the owner, from their usual IP
    // ...but a wrong password from that IP is still just a failed login, not a bypass of anything else
    expect((await login('owner@example.com', '203.0.113.10')).status).toBe(401);
  });

  it('counts failures only: successful logins do not use up the budget', async () => {
    await createUser('busy@example.com');
    for (let i = 0; i < 6; i++) {
      expect((await login('busy@example.com', '203.0.113.20', TEST_PASSWORD)).status).toBe(200);
    }
  });

  it('keeps a separate budget per account, and ignores case in the email', async () => {
    await createUser('a@example.com');
    await createUser('b@example.com');
    for (const [i, email] of ['a@example.com', 'A@Example.com', 'a@EXAMPLE.com'].entries()) {
      expect((await login(email, `198.51.100.${i + 1}`)).status).toBe(401);
    }
    expect((await login('a@example.com', '198.51.100.9')).status).toBe(429);
    expect((await login('b@example.com', '198.51.100.9')).status).toBe(401);
  });

  it('does not throttle requests that have no email to key on', async () => {
    for (let i = 0; i < 6; i++) {
      const res = await request(app).post('/api/v1/auth/login').send({});
      expect(res.status).toBe(400);
    }
  });
});

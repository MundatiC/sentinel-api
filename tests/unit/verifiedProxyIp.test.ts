import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import {
  CLIENT_IP_HEADER,
  PROXY_SECRET_HEADER,
  verifiedProxyIp,
} from '../../src/middleware/verifiedProxyIp.js';

const SECRET = 'a'.repeat(32);

function appWith(secret: string | undefined) {
  const app = express();
  app.set('trust proxy', 1);
  app.use(verifiedProxyIp(secret));
  app.get('/ip', (req, res) => {
    res.json({ ip: req.ip });
  });
  return app;
}

const ipOf = async (app: express.Express, headers: Record<string, string>) =>
  (await request(app).get('/ip').set(headers).set('X-Forwarded-For', '198.51.100.9')).body.ip;

describe('verifiedProxyIp', () => {
  const app = appWith(SECRET);

  it('uses the vouched IP when the secret matches', async () => {
    expect(
      await ipOf(app, { [PROXY_SECRET_HEADER]: SECRET, [CLIENT_IP_HEADER]: '203.0.113.5' }),
    ).toBe('203.0.113.5');
  });

  it('accepts an IPv6 address', async () => {
    expect(
      await ipOf(app, { [PROXY_SECRET_HEADER]: SECRET, [CLIENT_IP_HEADER]: '2001:db8::1' }),
    ).toBe('2001:db8::1');
  });

  it.each([
    ['no secret', {}],
    ['wrong secret', { [PROXY_SECRET_HEADER]: 'b'.repeat(32) }],
    ['shorter secret', { [PROXY_SECRET_HEADER]: 'a' }],
  ])('ignores the client-IP header with %s', async (_name, secretHeader) => {
    expect(await ipOf(app, { ...secretHeader, [CLIENT_IP_HEADER]: '203.0.113.5' })).toBe(
      '198.51.100.9',
    );
  });

  it('ignores a vouched value that is not an IP address', async () => {
    expect(
      await ipOf(app, { [PROXY_SECRET_HEADER]: SECRET, [CLIENT_IP_HEADER]: 'not-an-ip' }),
    ).toBe('198.51.100.9');
  });

  it('does nothing when no secret is configured', async () => {
    expect(
      await ipOf(appWith(undefined), {
        [PROXY_SECRET_HEADER]: SECRET,
        [CLIENT_IP_HEADER]: '203.0.113.5',
      }),
    ).toBe('198.51.100.9');
  });
});

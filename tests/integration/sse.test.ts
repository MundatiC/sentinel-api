import http from 'node:http';
import type { AddressInfo } from 'node:net';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { alertBus } from '../../src/modules/alerts/alertBus.js';
import {
  buildTestApp,
  createApiKey,
  createUser,
  loginAs,
  resetDb,
  sampleEvent,
  seedDefaultRules,
} from '../helpers.js';

const { app, env } = buildTestApp({}, { sseHeartbeatMs: 50 });
const server = http.createServer(app);
let port = 0;
const opened: http.IncomingMessage[] = [];

beforeEach(async () => {
  await resetDb();
  await seedDefaultRules();
  if (!server.listening) await new Promise<void>((resolve) => server.listen(0, resolve));
  port = (server.address() as AddressInfo).port;
});
afterEach(() => {
  for (const res of opened.splice(0)) res.destroy();
});

// Opens the stream like the dashboard will: a plain HTTP GET with a Bearer token.
function openStream(token?: string) {
  return new Promise<{
    res: http.IncomingMessage;
    data: () => string;
    waitFor: (text: string, ms?: number) => Promise<void>;
    ended: Promise<void>;
  }>((resolve, reject) => {
    const req = http.get(
      {
        port,
        path: '/api/v1/alerts/stream',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      },
      (res) => {
        opened.push(res);
        let buffer = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (buffer += chunk));
        const ended = new Promise<void>((done) => res.on('close', done));
        const waitFor = (text: string, ms = 3000) =>
          new Promise<void>((ok, fail) => {
            const started = Date.now();
            const timer = setInterval(() => {
              if (buffer.includes(text)) {
                clearInterval(timer);
                ok();
              } else if (Date.now() - started > ms) {
                clearInterval(timer);
                fail(new Error(`Timed out waiting for "${text}". Got: ${buffer}`));
              }
            }, 10);
          });
        resolve({ res, data: () => buffer, waitFor, ended });
      },
    );
    req.on('error', reject);
  });
}

async function viewerToken(email = 'v@example.com') {
  await createUser(email);
  return (await loginAs(app, email)).accessToken;
}

describe('GET /alerts/stream', () => {
  it('requires authentication', async () => {
    const stream = await openStream();
    expect(stream.res.statusCode).toBe(401);
  });

  it('streams alert.created as soon as the rules engine raises one', async () => {
    const stream = await openStream(await viewerToken());
    expect(stream.res.statusCode).toBe(200);
    expect(stream.res.headers['content-type']).toContain('text/event-stream');
    await stream.waitFor(': connected');

    const { raw } = await createApiKey();
    await request(app)
      .post('/api/v1/ingest/events')
      .set('X-API-Key', raw)
      .send({ events: Array.from({ length: 5 }, () => sampleEvent()) });

    await stream.waitFor('event: alert.created');
    expect(stream.data()).toContain('"ruleName":"Brute-force login attempts"');
    expect(stream.data()).toContain('"groupKey":"203.0.113.7"');
  });

  it('sends heartbeats', async () => {
    const stream = await openStream(await viewerToken());
    await stream.waitFor(': keep-alive');
  });

  it('cleans up its bus subscription when the client disconnects', async () => {
    const before = alertBus.listenerCount;
    const stream = await openStream(await viewerToken());
    await stream.waitFor(': connected');
    expect(alertBus.listenerCount).toBe(before + 1);
    stream.res.destroy();
    await stream.ended;
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(alertBus.listenerCount).toBe(before);
  });

  it('limits each user to 5 simultaneous streams', async () => {
    const token = await viewerToken();
    for (let i = 0; i < 5; i++) expect((await openStream(token)).res.statusCode).toBe(200);
    const sixth = await openStream(token);
    expect(sixth.res.statusCode).toBe(429);
    // another user is unaffected
    expect((await openStream(await viewerToken('other@example.com'))).res.statusCode).toBe(200);
  });

  it('closes the stream when the access token expires', async () => {
    const user = await createUser('short@example.com');
    const shortLived = jwt.sign({ role: 'VIEWER' }, env.JWT_ACCESS_SECRET, {
      subject: user.id,
      issuer: 'sentinel-api',
      expiresIn: 1,
    });
    const stream = await openStream(shortLived);
    expect(stream.res.statusCode).toBe(200);
    await Promise.race([
      stream.ended,
      new Promise((_, fail) => setTimeout(() => fail(new Error('stream stayed open')), 3000)),
    ]);
  });

  it('closes the stream when the user is deactivated', async () => {
    const token = await viewerToken();
    const stream = await openStream(token);
    await stream.waitFor(': connected');
    await prisma.user.updateMany({ data: { isActive: false } });
    await Promise.race([
      stream.ended,
      new Promise((_, fail) => setTimeout(() => fail(new Error('stream stayed open')), 3000)),
    ]);
  });
});

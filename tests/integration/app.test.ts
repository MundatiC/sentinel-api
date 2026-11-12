import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { buildTestApp } from '../helpers.js';

const { app } = buildTestApp();

describe('GET /api/v1/health', () => {
  it('returns ok', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('security headers', () => {
  it('sets helmet headers and hides x-powered-by', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toBe(
      "default-src 'none';frame-ancestors 'none'",
    );
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['strict-transport-security']).toBeDefined();
  });
});

describe('caching', () => {
  it('tells browsers, proxies and CDNs never to store API responses', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['cache-control']).toBe('no-store');
  });
});

describe('CORS', () => {
  it('allows the configured origin with credentials', async () => {
    const res = await request(app).get('/api/v1/health').set('Origin', 'http://localhost:3000');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:3000');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('does not allow an unknown origin', async () => {
    const res = await request(app).get('/api/v1/health').set('Origin', 'https://evil.example');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('request id', () => {
  it('generates one when missing', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('keeps a safe incoming id', async () => {
    const res = await request(app).get('/api/v1/health').set('X-Request-Id', 'trace-12345678');
    expect(res.headers['x-request-id']).toBe('trace-12345678');
  });

  it('replaces an unsafe incoming id', async () => {
    const res = await request(app).get('/api/v1/health').set('X-Request-Id', 'bad id with spaces!');
    expect(res.headers['x-request-id']).not.toBe('bad id with spaces!');
  });
});

describe('error handling', () => {
  it('returns the standard shape for unknown routes', async () => {
    const res = await request(app).get('/api/v1/nope');
    expect(res.status).toBe(404);
    expect(res.body.error).toMatchObject({ code: 'NOT_FOUND' });
    expect(res.body.error.requestId).toBeDefined();
  });

  it('returns 400 for malformed JSON without leaking internals', async () => {
    const res = await request(app)
      .post('/api/v1/health')
      .set('Content-Type', 'application/json')
      .send('{"broken":');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('BAD_REQUEST');
    expect(JSON.stringify(res.body)).not.toContain('SyntaxError');
  });

  it('returns 413 for bodies over the limit', async () => {
    const res = await request(app)
      .post('/api/v1/health')
      .send({ data: 'x'.repeat(200_000) });
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });
});

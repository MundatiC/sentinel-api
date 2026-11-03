/* eslint-disable @typescript-eslint/no-explicit-any -- the generated OpenAPI document is inspected as loose JSON in these tests */
import SwaggerParser from '@apidevtools/swagger-parser';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createOpenApiDocument, operations } from '../../src/lib/openapi.js';
import { buildTestApp } from '../helpers.js';

const { app } = buildTestApp();

describe('OpenAPI document', () => {
  it('is valid OpenAPI 3.1', async () => {
    const doc = JSON.parse(JSON.stringify(createOpenApiDocument()));
    await expect(SwaggerParser.validate(doc)).resolves.toBeTruthy();
  });

  it('is served as JSON', async () => {
    const res = await request(app).get('/api/v1/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.1.0');
    expect(Object.keys(res.body.paths)).toContain('/ingest/events');
  });

  it('generates request schemas from the real zod schemas', () => {
    const doc = createOpenApiDocument() as any;
    const schema = doc.paths['/ingest/events'].post.requestBody.content['application/json'].schema;
    expect(schema.properties.events.maxItems).toBe(500);
    const loginSchema =
      doc.paths['/auth/login'].post.requestBody.content['application/json'].schema;
    expect(loginSchema.additionalProperties).toBe(false); // strict objects reject unknown fields
    const eventsQuery = doc.paths['/events'].get.parameters.map((p: { name: string }) => p.name);
    expect(eventsQuery).toEqual(
      expect.arrayContaining(['severity', 'ip', 'from', 'to', 'q', 'pageSize']),
    );
  });

  it('marks protected operations with a security requirement and public ones without', () => {
    const doc = createOpenApiDocument() as any;
    expect(doc.paths['/health'].get.security).toEqual([]);
    expect(doc.paths['/users'].get.security).toEqual([{ bearerAuth: [] }]);
    expect(doc.paths['/ingest/events'].post.security).toEqual([{ apiKeyAuth: [] }]);
  });

  // Guards against documenting an endpoint that does not exist (docs drifting from the code).
  it('only documents routes that really exist', async () => {
    for (const o of operations) {
      const path = '/api/v1' + o.path.replace(/\{\w+\}/g, '00000000-0000-4000-8000-000000000000');
      const res = await request(app)[o.method](path);
      const routeMissing = res.status === 404 && res.body?.error?.message === 'Route not found';
      expect(
        routeMissing,
        `${o.method.toUpperCase()} ${o.path} is documented but not implemented`,
      ).toBe(false);
    }
  });
});

describe('Swagger UI', () => {
  it('serves the page with a locked-down CSP and no inline script', async () => {
    const res = await request(app).get('/docs');
    expect(res.status).toBe(200);
    const csp = res.headers['content-security-policy']!;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res.text).not.toMatch(/<script>[^<]/); // every script is an external file
  });

  it('serves its assets from our own server (no CDN)', async () => {
    const js = await request(app).get('/docs/assets/swagger-ui-bundle.js');
    expect(js.status).toBe(200);
    expect((await request(app).get('/docs/init.js')).status).toBe(200);
  });

  it('keeps the strict CSP on normal API routes', async () => {
    const res = await request(app).get('/api/v1/health');
    expect(res.headers['content-security-policy']).toBe(
      "default-src 'none';frame-ancestors 'none'",
    );
  });

  it('is switched off in production unless ENABLE_DOCS=true', async () => {
    const prod = buildTestApp({ NODE_ENV: 'production' }).app;
    expect((await request(prod).get('/docs')).status).toBe(404);
    expect((await request(prod).get('/api/v1/openapi.json')).status).toBe(404);
    const enabled = buildTestApp({ NODE_ENV: 'production', ENABLE_DOCS: 'true' }).app;
    expect((await request(enabled).get('/docs')).status).toBe(200);
  });
});

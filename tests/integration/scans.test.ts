import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { prisma } from '../../src/db/prisma.js';
import { buildTestApp, createUser, loginAs, resetDb } from '../helpers.js';

const { app } = buildTestApp();

beforeEach(resetDb);

async function makeScan() {
  return prisma.scan.create({
    data: {
      target: 'https://example.com',
      scannerVersion: '0.1.0',
      startedAt: new Date(),
      finishedAt: new Date(),
      summary: { HIGH: 1 },
      findings: {
        create: [
          {
            checkId: 'tls.old',
            category: 'TLS',
            severity: 'HIGH',
            title: 'Old TLS',
            description: 'd',
            remediation: 'r',
            references: [],
          },
          {
            checkId: 'headers.csp',
            category: 'HEADERS',
            severity: 'LOW',
            title: 'No CSP',
            description: 'd',
            remediation: 'r',
            references: [],
          },
        ],
      },
    },
  });
}

describe('scan reports', () => {
  it('require authentication', async () => {
    expect((await request(app).get('/api/v1/scans')).status).toBe(401);
  });

  it('list scans with their summary, and return one scan with findings grouped by category', async () => {
    await createUser('viewer@example.com');
    const { accessToken } = await loginAs(app, 'viewer@example.com');
    const scan = await makeScan();
    const auth = { Authorization: `Bearer ${accessToken}` };

    const list = await request(app).get('/api/v1/scans').set(auth);
    expect(list.body.data[0]).toMatchObject({ id: scan.id, summary: { HIGH: 1 } });
    expect(list.body.data[0].findings).toBeUndefined();

    const detail = await request(app).get(`/api/v1/scans/${scan.id}`).set(auth);
    expect(detail.body.scan.findings.map((f: { category: string }) => f.category)).toEqual([
      'HEADERS',
      'TLS',
    ]);

    expect(
      (await request(app).get('/api/v1/scans/00000000-0000-4000-8000-000000000000').set(auth))
        .status,
    ).toBe(404);
  });
});

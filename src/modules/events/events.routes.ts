import { Prisma } from '@prisma/client';
import { Router } from 'express';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { AppError } from '../../lib/errors.js';
import { paginated, skipTake } from '../../lib/pagination.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import {
  idParams,
  listEventsQuery,
  statsQuery,
  type ListEventsQuery,
  type StatsQuery,
} from './events.schemas.js';

// Prisma's `contains` becomes SQL `LIKE '%value%'` and does NOT escape the LIKE wildcards
// (% and _), so a search for "%" would match every row. Backslash is Postgres's LIKE escape character.
function escapeLike(value: string): string {
  return value.replace(/[\\%_]/g, '\\$&');
}

export function createEventsRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env), requireRole('VIEWER'));

  router.get('/', validate({ query: listEventsQuery }), async (_req, res) => {
    const query = res.locals.query as ListEventsQuery;

    // Build the filter from validated values only. Prisma turns this into a parameterized
    // query, so there is no string concatenation and therefore no SQL injection.
    const where: Prisma.EventWhereInput = {
      type: query.type,
      source: query.source,
      actor: query.actor,
      ip: query.ip,
      severity: query.severity ? { in: query.severity } : undefined,
      message: query.q ? { contains: escapeLike(query.q), mode: 'insensitive' } : undefined,
      occurredAt: query.from || query.to ? { gte: query.from, lte: query.to } : undefined,
    };

    const [events, total] = await Promise.all([
      prisma.event.findMany({
        where,
        orderBy: { occurredAt: query.sort === 'occurredAt:asc' ? 'asc' : 'desc' },
        ...skipTake(query),
      }),
      prisma.event.count({ where }),
    ]);
    res.json(paginated(events, total, query));
  });

  // Counts per time bucket and severity, for the dashboard charts.
  // (Declared before "/:id" so that "stats" is not mistaken for an id.)
  router.get('/stats', validate({ query: statsQuery }), async (_req, res) => {
    const { from, to, bucket } = res.locals.query as StatsQuery;
    // Raw SQL is needed for date_trunc. Prisma.sql sends every ${value} as a bound parameter,
    // never as part of the SQL text; `bucket` is also restricted to 'hour' | 'day' by zod.
    const rows = await prisma.$queryRaw<
      { bucket: Date; severity: string; count: bigint }[]
    >(Prisma.sql`
      SELECT date_trunc(${bucket}, "occurredAt") AS bucket, "severity"::text AS severity, COUNT(*) AS count
      FROM "Event"
      WHERE "occurredAt" >= ${from} AND "occurredAt" <= ${to}
      GROUP BY 1, 2
      ORDER BY 1`);

    const buckets = new Map<string, Record<string, number>>();
    for (const row of rows) {
      const key = row.bucket.toISOString();
      const entry = buckets.get(key) ?? { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
      entry[row.severity] = Number(row.count); // COUNT returns a bigint; JSON cannot hold those
      buckets.set(key, entry);
    }
    const data = [...buckets].map(([key, counts]) => ({
      bucket: key,
      ...counts,
      total: Object.values(counts).reduce((sum, n) => sum + n, 0),
    }));
    res.json({ from, to, bucket, data });
  });

  router.get('/:id', validate({ params: idParams }), async (_req, res) => {
    const { id } = res.locals.params as { id: string };
    const event = await prisma.event.findUnique({ where: { id } });
    if (!event) throw AppError.notFound('Event not found');
    res.json({ event });
  });

  return router;
}

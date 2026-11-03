import type { Prisma } from '@prisma/client';
import { Router } from 'express';
import { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { paginated, paginationQuery, skipTake } from '../../lib/pagination.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';

const isoDate = z.iso.datetime({ offset: true }).transform((value) => new Date(value));

export const listAuditQuery = paginationQuery.extend({
  actorId: z.uuid().optional(),
  action: z.string().max(100).optional(), // matches the start, so "auth." finds every auth action
  from: isoDate.optional(),
  to: isoDate.optional(),
});
type ListAuditQuery = z.infer<typeof listAuditQuery>;

export function createAuditRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env), requireRole('ADMIN'));

  router.get('/', validate({ query: listAuditQuery }), async (_req, res) => {
    const query = res.locals.query as ListAuditQuery;
    const where: Prisma.AuditLogWhereInput = {
      actorId: query.actorId,
      action: query.action ? { startsWith: query.action } : undefined,
      createdAt: query.from || query.to ? { gte: query.from, lte: query.to } : undefined,
    };
    const [rows, total] = await Promise.all([
      prisma.auditLog.findMany({ where, orderBy: { id: 'desc' }, ...skipTake(query) }),
      prisma.auditLog.count({ where }),
    ]);
    // The id column is a 64-bit integer (bigint), which JSON cannot represent: send it as a string.
    res.json(
      paginated(
        rows.map((row) => ({ ...row, id: row.id.toString() })),
        total,
        query,
      ),
    );
  });

  return router;
}

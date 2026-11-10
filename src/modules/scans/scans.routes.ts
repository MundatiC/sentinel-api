import { Router } from 'express';
import { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { AppError } from '../../lib/errors.js';
import { paginated, skipTake } from '../../lib/pagination.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import { listScansQuery, type ListScansQuery } from './scans.schemas.js';

const idParams = z.object({ id: z.uuid() });

export function createScansRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env), requireRole('VIEWER'));

  // The list returns the stored severity summary, not every finding, so it stays fast.
  router.get('/', validate({ query: listScansQuery }), async (_req, res) => {
    const query = res.locals.query as ListScansQuery;
    const where = query.target ? { target: query.target } : {};
    const [scans, total] = await Promise.all([
      prisma.scan.findMany({ where, orderBy: { createdAt: 'desc' }, ...skipTake(query) }),
      prisma.scan.count({ where }),
    ]);
    res.json(paginated(scans, total, query));
  });

  router.get('/:id', validate({ params: idParams }), async (_req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const scan = await prisma.scan.findUnique({
      where: { id },
      include: { findings: { orderBy: [{ category: 'asc' }, { title: 'asc' }] } },
    });
    if (!scan) throw AppError.notFound('Scan not found');
    res.json({ scan });
  });

  return router;
}

import { Role } from '@prisma/client';
import { Router } from 'express';
import { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { AppError } from '../../lib/errors.js';
import { clientMeta } from '../../lib/clientMeta.js';
import {
  paginated,
  paginationQuery,
  skipTake,
  type PaginationQuery,
} from '../../lib/pagination.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import { recordAudit } from '../audit/audit.service.js';
import { toPublicUser } from '../auth/auth.service.js';

const idParams = z.object({ id: z.uuid() });
export const updateUserBody = z
  .strictObject({ role: z.enum(Role).optional(), isActive: z.boolean().optional() })
  .refine((value) => value.role !== undefined || value.isActive !== undefined, {
    message: 'Provide role and/or isActive',
  });

export function createUsersRouter(env: Env) {
  const router = Router();
  // Every route in this file is admin-only. Applying it once here means a route added
  // later cannot accidentally forget it.
  router.use(authenticate(env), requireRole('ADMIN'));

  router.get('/', validate({ query: paginationQuery }), async (_req, res) => {
    const query = res.locals.query as PaginationQuery;
    const [users, total] = await Promise.all([
      prisma.user.findMany({ orderBy: { createdAt: 'desc' }, ...skipTake(query) }),
      prisma.user.count(),
    ]);
    res.json(
      paginated(
        users.map((u) => ({ ...toPublicUser(u), lastLoginAt: u.lastLoginAt })),
        total,
        query,
      ),
    );
  });

  router.patch('/:id', validate({ params: idParams, body: updateUserBody }), async (req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const { role, isActive } = req.body as z.infer<typeof updateUserBody>;

    // An admin cannot lock themselves out or demote themselves.
    if (id === req.user!.id) {
      throw AppError.badRequest('You cannot change your own role or active status');
    }
    const target = await prisma.user.findUnique({ where: { id } });
    if (!target) throw AppError.notFound('User not found');

    const updated = await prisma.$transaction(async (tx) => {
      const user = await tx.user.update({ where: { id }, data: { role, isActive } });
      if (isActive === false) {
        // Deactivation must end existing sessions straight away.
        await tx.refreshToken.updateMany({
          where: { userId: id, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
      return user;
    });

    await recordAudit({
      actorType: 'USER',
      actorId: req.user!.id,
      action: role !== undefined && role !== target.role ? 'user.role_changed' : 'user.updated',
      targetType: 'User',
      targetId: id,
      metadata: {
        from: { role: target.role, isActive: target.isActive },
        to: { role: updated.role, isActive: updated.isActive },
      },
      ...clientMeta(req),
    });
    res.json({ user: toPublicUser(updated) });
  });

  return router;
}

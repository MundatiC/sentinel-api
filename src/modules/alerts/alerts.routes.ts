import type { Prisma } from '@prisma/client';
import { Router } from 'express';
import type { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { clientMeta } from '../../lib/clientMeta.js';
import { AppError } from '../../lib/errors.js';
import { paginated, skipTake } from '../../lib/pagination.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import { recordAudit } from '../audit/audit.service.js';
import { alertBus } from './alertBus.js';
import {
  idParams,
  listAlertsQuery,
  updateAlertBody,
  type ListAlertsQuery,
  type UpdateAlertBody,
} from './alerts.schemas.js';
import { toAlertView } from './engine.js';
import { alertStream } from './sse.js';

export function createAlertsRouter(env: Env, options: { heartbeatMs?: number } = {}) {
  const router = Router();
  router.use(authenticate(env), requireRole('VIEWER'));

  router.get('/', validate({ query: listAlertsQuery }), async (_req, res) => {
    const query = res.locals.query as ListAlertsQuery;
    const where: Prisma.AlertWhereInput = {
      status: query.status ? { in: query.status } : undefined,
      severity: query.severity ? { in: query.severity } : undefined,
      ruleId: query.ruleId,
    };
    const [alerts, total] = await Promise.all([
      prisma.alert.findMany({
        where,
        include: { rule: { select: { name: true } } },
        orderBy: { createdAt: 'desc' },
        ...skipTake(query),
      }),
      prisma.alert.count({ where }),
    ]);
    res.json(paginated(alerts, total, query));
  });

  // Live feed. Declared before "/:id" so "stream" is not parsed as an id.
  router.get('/stream', alertStream(options.heartbeatMs));

  router.get('/:id', validate({ params: idParams }), async (_req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const alert = await prisma.alert.findUnique({
      where: { id },
      include: {
        rule: true,
        events: { include: { event: true }, orderBy: { event: { occurredAt: 'desc' } }, take: 100 },
      },
    });
    if (!alert) throw AppError.notFound('Alert not found');
    const { events, ...rest } = alert;
    res.json({ alert: { ...rest, events: events.map((link) => link.event) } });
  });

  router.patch(
    '/:id',
    requireRole('ANALYST'),
    validate({ params: idParams, body: updateAlertBody }),
    async (req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      const body = req.body as UpdateAlertBody;
      const alert = await prisma.alert.findUnique({
        where: { id },
        include: { rule: { select: { name: true } } },
      });
      if (!alert) throw AppError.notFound('Alert not found');

      const data: Prisma.AlertUncheckedUpdateInput = {};
      const actions: string[] = [];

      if (body.status) {
        // Allowed moves: OPEN -> ACKNOWLEDGED, and OPEN/ACKNOWLEDGED -> RESOLVED. A resolved alert
        // stays resolved: if the attack continues, the engine raises a NEW alert after the cooldown.
        const allowed =
          (body.status === 'ACKNOWLEDGED' && alert.status === 'OPEN') ||
          (body.status === 'RESOLVED' && alert.status !== 'RESOLVED');
        if (!allowed) {
          throw new AppError(
            409,
            'INVALID_TRANSITION',
            `Cannot change an alert from ${alert.status} to ${body.status}`,
          );
        }
        data.status = body.status;
        if (body.status === 'ACKNOWLEDGED') {
          data.acknowledgedAt = new Date();
          data.acknowledgedById = req.user!.id;
          actions.push('alert.acknowledged');
        } else {
          data.resolvedAt = new Date();
          data.resolvedById = req.user!.id;
          actions.push('alert.resolved');
        }
      }

      if (body.assigneeId !== undefined) {
        if (body.assigneeId !== null) {
          const assignee = await prisma.user.findUnique({ where: { id: body.assigneeId } });
          if (!assignee || !assignee.isActive || assignee.role === 'VIEWER') {
            throw AppError.badRequest('Assignee must be an active analyst or admin');
          }
        }
        data.assigneeId = body.assigneeId;
        actions.push('alert.assigned');
      }

      const updated = await prisma.alert.update({ where: { id }, data });
      for (const action of actions) {
        await recordAudit({
          actorType: 'USER',
          actorId: req.user!.id,
          action,
          targetType: 'Alert',
          targetId: id,
          metadata: { status: updated.status, assigneeId: updated.assigneeId },
          ...clientMeta(req),
        });
      }
      alertBus.publish({ type: 'alert.updated', alert: toAlertView(updated, alert.rule.name) });
      res.json({ alert: updated });
    },
  );

  return router;
}

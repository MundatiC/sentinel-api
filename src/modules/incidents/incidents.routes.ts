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
import {
  addNoteBody,
  createIncidentBody,
  idParams,
  linkAlertBody,
  listIncidentsQuery,
  updateIncidentBody,
  type CreateIncidentBody,
  type ListIncidentsQuery,
  type UpdateIncidentBody,
} from './incidents.schemas.js';
import { getIncidentDetail, linkAlert } from './incidents.service.js';

export function createIncidentsRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env), requireRole('VIEWER'));

  router.get('/', validate({ query: listIncidentsQuery }), async (_req, res) => {
    const query = res.locals.query as ListIncidentsQuery;
    const where: Prisma.IncidentWhereInput = {
      status: query.status ? { in: query.status } : undefined,
      severity: query.severity ? { in: query.severity } : undefined,
    };
    const [incidents, total] = await Promise.all([
      prisma.incident.findMany({
        where,
        include: { _count: { select: { alerts: true } } },
        orderBy: { createdAt: 'desc' },
        ...skipTake(query),
      }),
      prisma.incident.count({ where }),
    ]);
    res.json(
      paginated(
        incidents.map(({ _count, ...i }) => ({ ...i, alertCount: _count.alerts })),
        total,
        query,
      ),
    );
  });

  router.get('/:id', validate({ params: idParams }), async (_req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    res.json({ incident: await getIncidentDetail(id) });
  });

  router.post(
    '/',
    requireRole('ANALYST'),
    validate({ body: createIncidentBody }),
    async (req, res) => {
      const body = req.body as CreateIncidentBody;
      const userId = req.user!.id;
      // One transaction: the incident, its first timeline entry and the alert links all succeed or none do.
      const id = await prisma.$transaction(async (tx) => {
        const incident = await tx.incident.create({
          data: {
            title: body.title,
            severity: body.severity,
            summary: body.summary,
            createdById: userId,
          },
        });
        await tx.incidentTimelineEntry.create({
          data: {
            incidentId: incident.id,
            kind: 'STATUS_CHANGE',
            body: 'Incident opened',
            authorId: userId,
          },
        });
        for (const alertId of new Set(body.alertIds))
          await linkAlert(tx, incident.id, alertId, userId);
        return incident.id;
      });
      await recordAudit({
        actorType: 'USER',
        actorId: userId,
        action: 'incident.created',
        targetType: 'Incident',
        targetId: id,
        metadata: { title: body.title, alertCount: body.alertIds.length },
        ...clientMeta(req),
      });
      res.status(201).json({ incident: await getIncidentDetail(id) });
    },
  );

  router.patch(
    '/:id',
    requireRole('ANALYST'),
    validate({ params: idParams, body: updateIncidentBody }),
    async (req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      const body = req.body as UpdateIncidentBody;
      const current = await prisma.incident.findUnique({ where: { id } });
      if (!current) throw AppError.notFound('Incident not found');

      const statusChanged = body.status !== undefined && body.status !== current.status;
      await prisma.$transaction(async (tx) => {
        await tx.incident.update({
          where: { id },
          data: {
            ...body,
            // resolvedAt follows the status: set when resolved, cleared if the incident is reopened.
            ...(statusChanged
              ? { resolvedAt: body.status === 'RESOLVED' ? new Date() : null }
              : {}),
          },
        });
        if (statusChanged) {
          await tx.incidentTimelineEntry.create({
            data: {
              incidentId: id,
              kind: 'STATUS_CHANGE',
              body: `Status changed from ${current.status} to ${body.status}`,
              authorId: req.user!.id,
            },
          });
        }
      });
      await recordAudit({
        actorType: 'USER',
        actorId: req.user!.id,
        action: statusChanged ? 'incident.status_changed' : 'incident.updated',
        targetType: 'Incident',
        targetId: id,
        metadata: {
          changed: Object.keys(body),
          ...(statusChanged ? { from: current.status, to: body.status ?? null } : {}),
        },
        ...clientMeta(req),
      });
      res.json({ incident: await getIncidentDetail(id) });
    },
  );

  router.post(
    '/:id/timeline',
    requireRole('ANALYST'),
    validate({ params: idParams, body: addNoteBody }),
    async (req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      if (!(await prisma.incident.findUnique({ where: { id }, select: { id: true } })))
        throw AppError.notFound('Incident not found');
      const entry = await prisma.incidentTimelineEntry.create({
        data: {
          incidentId: id,
          kind: 'NOTE',
          body: req.body.body,
          occurredAt: req.body.occurredAt,
          authorId: req.user!.id,
        },
      });
      await recordAudit({
        actorType: 'USER',
        actorId: req.user!.id,
        action: 'incident.note_added',
        targetType: 'Incident',
        targetId: id,
        ...clientMeta(req),
      });
      res.status(201).json({ entry });
    },
  );

  router.post(
    '/:id/alerts',
    requireRole('ANALYST'),
    validate({ params: idParams, body: linkAlertBody }),
    async (req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      if (!(await prisma.incident.findUnique({ where: { id }, select: { id: true } })))
        throw AppError.notFound('Incident not found');
      const linked = await prisma.$transaction((tx) =>
        linkAlert(tx, id, req.body.alertId, req.user!.id),
      );
      if (linked) {
        await recordAudit({
          actorType: 'USER',
          actorId: req.user!.id,
          action: 'incident.alert_linked',
          targetType: 'Incident',
          targetId: id,
          metadata: { alertId: req.body.alertId },
          ...clientMeta(req),
        });
      }
      res.status(linked ? 201 : 200).json({ incident: await getIncidentDetail(id) });
    },
  );

  return router;
}

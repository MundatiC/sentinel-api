import { GroupBy, Prisma, Severity } from '@prisma/client';
import { Router } from 'express';
import { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { clientMeta } from '../../lib/clientMeta.js';
import { AppError } from '../../lib/errors.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import { recordAudit } from '../audit/audit.service.js';

const ruleFields = z.strictObject({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(500).default(''),
  enabled: z.boolean().default(true),
  eventType: z
    .string()
    .max(100)
    .regex(/^[a-z0-9_]+(\.[a-z0-9_]+)+$/, 'eventType must look like "auth.login_failed"'),
  groupBy: z.enum(GroupBy).default('IP'),
  threshold: z.number().int().min(1).max(10_000),
  windowSeconds: z.number().int().min(1).max(86_400),
  severity: z.enum(Severity),
  cooldownSeconds: z.number().int().min(0).max(86_400).default(300),
});
const createBody = ruleFields;
const updateBody = ruleFields
  .partial()
  .refine((value) => Object.keys(value).length > 0, 'Provide at least one field');
const idParams = z.object({ id: z.uuid() });

function isPrismaError(err: unknown, code: string) {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === code;
}

export function createRulesRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env));

  // Anyone logged in can SEE the rules; only admins can change them.
  router.get('/', requireRole('VIEWER'), async (_req, res) => {
    res.json({ data: await prisma.alertRule.findMany({ orderBy: { name: 'asc' } }) });
  });

  router.post('/', requireRole('ADMIN'), validate({ body: createBody }), async (req, res) => {
    try {
      const rule = await prisma.alertRule.create({ data: req.body });
      await recordAudit({
        actorType: 'USER',
        actorId: req.user!.id,
        action: 'alert_rule.created',
        targetType: 'AlertRule',
        targetId: rule.id,
        metadata: { name: rule.name },
        ...clientMeta(req),
      });
      res.status(201).json({ rule });
    } catch (err) {
      if (isPrismaError(err, 'P2002'))
        throw new AppError(409, 'RULE_NAME_TAKEN', 'A rule with this name already exists');
      throw err;
    }
  });

  router.patch(
    '/:id',
    requireRole('ADMIN'),
    validate({ params: idParams, body: updateBody }),
    async (req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      try {
        const rule = await prisma.alertRule.update({ where: { id }, data: req.body });
        await recordAudit({
          actorType: 'USER',
          actorId: req.user!.id,
          action: 'alert_rule.updated',
          targetType: 'AlertRule',
          targetId: id,
          metadata: { changed: Object.keys(req.body) },
          ...clientMeta(req),
        });
        res.json({ rule });
      } catch (err) {
        if (isPrismaError(err, 'P2025')) throw AppError.notFound('Rule not found');
        if (isPrismaError(err, 'P2002'))
          throw new AppError(409, 'RULE_NAME_TAKEN', 'A rule with this name already exists');
        throw err;
      }
    },
  );

  router.delete('/:id', requireRole('ADMIN'), validate({ params: idParams }), async (req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    try {
      await prisma.alertRule.delete({ where: { id } });
    } catch (err) {
      if (isPrismaError(err, 'P2025')) throw AppError.notFound('Rule not found');
      // Alerts reference their rule (ON DELETE RESTRICT) so that alert history is never lost.
      if (isPrismaError(err, 'P2003')) {
        throw new AppError(
          409,
          'RULE_IN_USE',
          'This rule has alerts. Disable it instead of deleting it.',
        );
      }
      throw err;
    }
    await recordAudit({
      actorType: 'USER',
      actorId: req.user!.id,
      action: 'alert_rule.deleted',
      targetType: 'AlertRule',
      targetId: id,
      ...clientMeta(req),
    });
    res.status(204).end();
  });

  return router;
}

import { Router } from 'express';
import { z } from 'zod';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { API_KEY_SCOPES, generateApiKey } from '../../lib/apiKey.js';
import { clientMeta } from '../../lib/clientMeta.js';
import { AppError } from '../../lib/errors.js';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { validate } from '../../middleware/validate.js';
import { recordAudit } from '../audit/audit.service.js';

const createBody = z.strictObject({
  name: z.string().trim().min(1).max(100),
  scopes: z
    .array(z.enum(API_KEY_SCOPES))
    .min(1)
    .refine((s) => new Set(s).size === s.length, 'Duplicate scopes'),
  expiresAt: z.iso
    .datetime({ offset: true })
    .transform((value) => new Date(value))
    .refine((date) => date > new Date(), 'expiresAt must be in the future')
    .optional(),
});
const idParams = z.object({ id: z.uuid() });

// Never expose keyHash.
const publicKey = {
  id: true,
  name: true,
  prefix: true,
  scopes: true,
  lastUsedAt: true,
  expiresAt: true,
  revokedAt: true,
  createdAt: true,
} as const;

export function createApiKeysRouter(env: Env) {
  const router = Router();
  router.use(authenticate(env), requireRole('ADMIN'));

  router.get('/', async (_req, res) => {
    const keys = await prisma.apiKey.findMany({
      select: publicKey,
      orderBy: { createdAt: 'desc' },
    });
    res.json({ data: keys });
  });

  router.post('/', validate({ body: createBody }), async (req, res) => {
    const body = req.body as z.infer<typeof createBody>;
    const { raw, prefix, hash } = generateApiKey();
    const key = await prisma.apiKey.create({
      data: {
        name: body.name,
        scopes: body.scopes,
        expiresAt: body.expiresAt,
        prefix,
        keyHash: hash,
        createdById: req.user!.id,
      },
      select: publicKey,
    });
    await recordAudit({
      actorType: 'USER',
      actorId: req.user!.id,
      action: 'api_key.created',
      targetType: 'ApiKey',
      targetId: key.id,
      metadata: { name: key.name, scopes: key.scopes, prefix },
      ...clientMeta(req),
    });
    // The ONLY time the full key is ever returned. We keep just its hash, so it cannot be shown again.
    res.status(201).json({ apiKey: key, key: raw });
  });

  router.delete('/:id', validate({ params: idParams }), async (req, res) => {
    const { id } = res.locals.params as z.infer<typeof idParams>;
    const key = await prisma.apiKey.findUnique({ where: { id } });
    if (!key) throw AppError.notFound('API key not found');
    if (!key.revokedAt) {
      await prisma.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
      await recordAudit({
        actorType: 'USER',
        actorId: req.user!.id,
        action: 'api_key.revoked',
        targetType: 'ApiKey',
        targetId: id,
        metadata: { name: key.name, prefix: key.prefix },
        ...clientMeta(req),
      });
    }
    res.status(204).end();
  });

  return router;
}

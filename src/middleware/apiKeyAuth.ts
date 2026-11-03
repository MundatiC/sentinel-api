import type { RequestHandler } from 'express';
import { prisma } from '../db/prisma.js';
import { parseApiKey, type ApiKeyScope } from '../lib/apiKey.js';
import { safeEqualHex, sha256 } from '../lib/crypto.js';
import { AppError } from '../lib/errors.js';

export interface AuthApiKey {
  id: string;
  name: string;
  scopes: string[];
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiKey?: AuthApiKey;
    }
  }
}

const LAST_USED_UPDATE_INTERVAL_MS = 60_000;

// Authenticates machines (the scanner, log shippers) with an `X-API-Key` header and checks the
// key carries the scope this route needs. Keys can only write data; they cannot read anything
// or call user endpoints, because those routes use `authenticate` (JWT) instead.
export function apiKeyAuth(requiredScope: ApiKeyScope): RequestHandler {
  return async (req, _res, next) => {
    const raw = req.get('x-api-key');
    const parsed = raw ? parseApiKey(raw) : null;
    // Same message for every failure so callers cannot tell "unknown key" from "revoked key".
    const fail = () => AppError.unauthorized('Invalid API key');
    if (!raw || !parsed) throw fail();

    const key = await prisma.apiKey.findUnique({ where: { prefix: parsed.prefix } });
    if (!key || !safeEqualHex(key.keyHash, sha256(raw))) throw fail();
    if (key.revokedAt || (key.expiresAt && key.expiresAt <= new Date())) throw fail();

    if (!key.scopes.includes(requiredScope)) {
      throw AppError.forbidden(`This API key lacks the "${requiredScope}" scope`);
    }

    // Record usage, but at most once a minute so a busy scanner does not cause a write per request.
    if (!key.lastUsedAt || Date.now() - key.lastUsedAt.getTime() > LAST_USED_UPDATE_INTERVAL_MS) {
      await prisma.apiKey.update({ where: { id: key.id }, data: { lastUsedAt: new Date() } });
    }

    req.apiKey = { id: key.id, name: key.name, scopes: key.scopes };
    next();
  };
}

import type { RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import type { Env } from '../config/env.js';
import { prisma } from '../db/prisma.js';
import { AppError } from '../lib/errors.js';

// Counters live in memory, which is fine for one API instance. With several instances you would
// switch to a shared store (e.g. Redis) so all of them count together.
function limiter(
  limit: number,
  windowMinutes: number,
  key?: (ip: string, body: unknown) => string,
) {
  return rateLimit({
    limit,
    windowMs: windowMinutes * 60_000,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => {
      // ipKeyGenerator groups IPv6 addresses by /56 so one user cannot dodge limits by rotating
      // addresses inside their own block.
      const ip = ipKeyGenerator(req.ip ?? 'unknown');
      return key ? key(ip, req.body) : ip;
    },
    handler: (_req, _res, next) =>
      next(new AppError(429, 'RATE_LIMITED', 'Too many requests, slow down')),
  });
}

const KNOWN_IP_DAYS = 30;

// Normalised login email from a request body, or '' when there is none.
function loginEmail(body: unknown): string {
  return typeof body === 'object' &&
    body !== null &&
    'email' in body &&
    typeof body.email === 'string'
    ? body.email.toLowerCase().trim().slice(0, 254)
    : '';
}

// Has this IP logged in to this account successfully in the last 30 days? Read from the audit log.
async function isKnownIp(email: string, ip: string | undefined): Promise<boolean> {
  if (!ip) return false;
  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (!user) return false;
  const since = new Date(Date.now() - KNOWN_IP_DAYS * 86_400_000);
  const seen = await prisma.auditLog.findFirst({
    where: { actorId: user.id, action: 'auth.login', ip, createdAt: { gte: since } },
    select: { id: true },
  });
  return seen !== null;
}

// Failed logins per ACCOUNT, across all IPs, so rotating IPs does not reset the budget. A hard per-account
// lock would let anyone who knows the email lock the owner out (a denial of service), so once the budget is
// spent we still let through IPs that already logged in to this account successfully; only unfamiliar
// IPs get a 429. Only failures count: a successful login gives its slot back.
function accountLoginLimiter(limit: number, windowMinutes: number): RequestHandler {
  return rateLimit({
    limit,
    windowMs: windowMinutes * 60_000,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    skip: (req) => loginEmail(req.body) === '', // nothing to key on: the validator will reject it
    keyGenerator: (req) => loginEmail(req.body),
    handler: (req, _res, next) => {
      isKnownIp(loginEmail(req.body), req.ip).then(
        (known) =>
          next(
            known ? undefined : new AppError(429, 'RATE_LIMITED', 'Too many requests, slow down'),
          ),
        next,
      );
    },
  });
}

// Run the per-IP limiter, then the per-account one.
function loginLimiters(byIp: RequestHandler, byAccount: RequestHandler): RequestHandler {
  return (req, res, next) => byIp(req, res, (err) => (err ? next(err) : byAccount(req, res, next)));
}

export function createRateLimiters(env: Env): {
  global: RequestHandler;
  login: RequestHandler;
  ingest: RequestHandler;
  ingestByIp: RequestHandler;
} {
  return {
    global: limiter(env.GLOBAL_RATE_LIMIT, env.RATE_LIMIT_WINDOW_MINUTES),
    // Runs BEFORE API-key auth: caps how fast one IP can guess keys or flood us with junk.
    ingestByIp: limiter(env.INGEST_RATE_LIMIT * 5, 1),
    // Runs AFTER API-key auth, so the limit is per key (a noisy scanner cannot starve another one).
    ingest: rateLimit({
      limit: env.INGEST_RATE_LIMIT,
      windowMs: 60_000,
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      keyGenerator: (req) => req.apiKey?.id ?? ipKeyGenerator(req.ip ?? 'unknown'),
      handler: (_req, _res, next) =>
        next(new AppError(429, 'RATE_LIMITED', 'Too many requests, slow down')),
    }),
    // Login is limited per IP+email (one IP guessing many passwords for one account, or many accounts) and
    // per account across IPs (see accountLoginLimiter).
    login: loginLimiters(
      limiter(
        env.LOGIN_RATE_LIMIT,
        env.RATE_LIMIT_WINDOW_MINUTES,
        (ip, body) => `${ip}|${loginEmail(body)}`,
      ),
      accountLoginLimiter(env.ACCOUNT_LOGIN_RATE_LIMIT, env.RATE_LIMIT_WINDOW_MINUTES),
    ),
  };
}

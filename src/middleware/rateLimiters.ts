import type { RequestHandler } from 'express';
import { ipKeyGenerator, rateLimit } from 'express-rate-limit';
import type { Env } from '../config/env.js';
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
    // Login is limited per IP AND per email: stops one IP guessing many passwords for one
    // account, and stops guessing many accounts from one IP.
    login: limiter(env.LOGIN_RATE_LIMIT, env.RATE_LIMIT_WINDOW_MINUTES, (ip, body) => {
      const email =
        typeof body === 'object' &&
        body !== null &&
        'email' in body &&
        typeof body.email === 'string'
          ? body.email.toLowerCase().trim().slice(0, 254)
          : '';
      return `${ip}|${email}`;
    }),
  };
}

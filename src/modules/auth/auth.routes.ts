import { Router, type CookieOptions, type RequestHandler, type Response } from 'express';
import type { Env } from '../../config/env.js';
import { AppError } from '../../lib/errors.js';
import { clientMeta } from '../../lib/clientMeta.js';
import { authenticate } from '../../middleware/authenticate.js';
import { validate } from '../../middleware/validate.js';
import { toPublicUser } from './auth.service.js';
import * as auth from './auth.service.js';
import { loginBody, registerBody } from './auth.schemas.js';
import { prisma } from '../../db/prisma.js';
import { EventTypes } from '../../lib/eventTypes.js';
import type { EventPipeline } from '../alerts/pipeline.js';

const COOKIE_NAME = 'sentinel_refresh';

export function createAuthRouter(env: Env, loginLimiter: RequestHandler, pipeline: EventPipeline) {
  const router = Router();

  // httpOnly: JavaScript cannot read the cookie, so XSS cannot steal it.
  // Secure:   only sent over HTTPS (in production).
  // SameSite=Strict: browsers never attach it to cross-site requests, which blocks CSRF.
  // path:     the cookie is only sent to the auth endpoints, not to every API call.
  const cookieOptions = (): CookieOptions => ({
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: 'strict',
    path: '/api/v1/auth',
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 86_400_000,
  });
  const setRefreshCookie = (res: Response, token: string) =>
    res.cookie(COOKIE_NAME, token, cookieOptions());
  const clearRefreshCookie = (res: Response) =>
    res.clearCookie(COOKIE_NAME, { ...cookieOptions(), maxAge: undefined });

  router.post('/register', validate({ body: registerBody }), async (req, res) => {
    if (!env.ALLOW_REGISTRATION) {
      throw new AppError(403, 'REGISTRATION_DISABLED', 'Self-registration is disabled');
    }
    res.status(201).json({ user: await auth.register(req.body, clientMeta(req)) });
  });

  router.post('/login', loginLimiter, validate({ body: loginBody }), async (req, res) => {
    const meta = clientMeta(req);
    let result;
    try {
      result = await auth.login(req.body, env, meta);
    } catch (err) {
      // Sentinel monitors itself: a failed login becomes a security event, so repeated failures
      // from one IP trip the same brute-force rule used for any other application.
      if (err instanceof AppError && err.code === 'INVALID_CREDENTIALS') {
        await pipeline.record({
          type: EventTypes.LoginFailed,
          severity: 'MEDIUM',
          source: 'sentinel-api',
          actor: req.body.email,
          ip: meta.ip,
          message: `Failed login attempt for ${req.body.email}`,
        });
      }
      throw err;
    }
    await pipeline.record({
      type: EventTypes.LoginSuccess,
      severity: 'INFO',
      source: 'sentinel-api',
      actor: result.user.email,
      ip: meta.ip,
      message: `Successful login for ${result.user.email}`,
    });
    setRefreshCookie(res, result.refreshToken);
    res.json({ accessToken: result.accessToken, user: result.user });
  });

  router.post('/refresh', async (req, res) => {
    const token: unknown = req.cookies?.[COOKIE_NAME];
    if (typeof token !== 'string' || !token) throw AppError.unauthorized('No session');
    try {
      const result = await auth.refresh(token, env, clientMeta(req));
      setRefreshCookie(res, result.refreshToken);
      res.json({ accessToken: result.accessToken, user: result.user });
    } catch (err) {
      clearRefreshCookie(res); // a dead cookie is useless; drop it
      throw err;
    }
  });

  router.post('/logout', async (req, res) => {
    const token: unknown = req.cookies?.[COOKIE_NAME];
    await auth.logout(typeof token === 'string' ? token : undefined, clientMeta(req));
    clearRefreshCookie(res);
    res.status(204).end();
  });

  router.get('/me', authenticate(env), async (req, res) => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: req.user!.id } });
    res.json({ user: toPublicUser(user) });
  });

  return router;
}

import cookieParser from 'cookie-parser';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import type { Env } from './config/env.js';
import type { Logger } from './lib/logger.js';
import { createErrorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { createRateLimiters } from './middleware/rateLimiters.js';
import { requestId } from './middleware/requestId.js';
import { createAuthRouter } from './modules/auth/auth.routes.js';
import { createUsersRouter } from './modules/users/users.routes.js';
import { healthRouter } from './modules/health/health.routes.js';

// The app is built by a function, and does NOT call listen(). That lets tests (supertest)
// use it without opening a real port.
export function createApp(env: Env, logger: Logger) {
  const app = express();

  app.disable('x-powered-by'); // don't advertise "Express" to scanners
  app.set('trust proxy', env.TRUST_PROXY);

  app.use(requestId);
  app.use(pinoHttp({ logger, genReqId: (_req, res) => res.locals.requestId }));

  // This API only returns JSON, so the strictest possible CSP is fine: nothing may load.
  // `useDefaults: false` matters: otherwise helmet MERGES its own looser defaults
  // (script-src 'self', style-src ... 'unsafe-inline') into our policy.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
      },
      frameguard: { action: 'deny' },
    }),
  );

  // CORS allowlist: only the configured dashboard origin(s) may call us from a browser.
  // `credentials: true` is required so the browser sends the refresh-token cookie.
  app.use(cors({ origin: env.CORS_ORIGINS, credentials: true }));

  // Small body limit by default; routes that legitimately need more (batch ingest) opt in.
  app.use(express.json({ limit: '100kb' }));

  app.use(cookieParser());

  const limiters = createRateLimiters(env);
  app.use(limiters.global);

  app.use('/api/v1', healthRouter);
  app.use('/api/v1/auth', createAuthRouter(env, limiters.login));
  app.use('/api/v1/users', createUsersRouter(env));

  app.use(notFoundHandler);
  app.use(createErrorHandler(logger));

  return app;
}

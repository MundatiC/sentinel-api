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
import { createApiKeysRouter } from './modules/apiKeys/apiKeys.routes.js';
import { createEventsRouter } from './modules/events/events.routes.js';
import { createIngestRouter } from './modules/ingest/ingest.routes.js';
import { createScansRouter } from './modules/scans/scans.routes.js';
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

  app.use(cookieParser());

  const limiters = createRateLimiters(env);

  // Machine ingestion is mounted BEFORE the global limiter and JSON parser: it has its own
  // per-IP and per-API-key limits and a larger (1 MB) body limit, applied after authentication.
  app.use('/api/v1/ingest', createIngestRouter(limiters.ingest, limiters.ingestByIp));

  app.use(limiters.global);

  // Small body limit by default; routes that legitimately need more (batch ingest) opt in.
  app.use(express.json({ limit: '100kb' }));

  app.use('/api/v1', healthRouter);
  app.use('/api/v1/auth', createAuthRouter(env, limiters.login));
  app.use('/api/v1/users', createUsersRouter(env));
  app.use('/api/v1/api-keys', createApiKeysRouter(env));
  app.use('/api/v1/events', createEventsRouter(env));
  app.use('/api/v1/scans', createScansRouter(env));

  app.use(notFoundHandler);
  app.use(createErrorHandler(logger));

  return app;
}

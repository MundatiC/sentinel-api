import express, { Router, type RequestHandler } from 'express';
import { apiKeyAuth } from '../../middleware/apiKeyAuth.js';
import { validate } from '../../middleware/validate.js';
import { ingestEventsBody, ingestScanBody } from './ingest.schemas.js';
import { ingestEvents, ingestScan } from './ingest.service.js';

// Order matters here, and is deliberate:
//   0. rate limit per IP          -> stops key guessing and floods
//   1. authenticate the API key   -> unauthenticated callers cost us almost nothing
//   2. rate limit per key
//   3. only THEN parse the (larger, 1 MB) body
// This router is mounted in app.ts BEFORE the global 100 kb JSON parser for that reason.
export function createIngestRouter(ingestLimiter: RequestHandler, ingestByIp: RequestHandler) {
  const router = Router();
  router.use(ingestByIp);

  router.post(
    '/events',
    apiKeyAuth('events:write'),
    ingestLimiter,
    express.json({ limit: '1mb' }),
    validate({ body: ingestEventsBody }),
    async (req, res) => {
      const created = await ingestEvents(req.body.events, req.apiKey!.id);
      res.status(201).json({ accepted: created.length });
    },
  );

  router.post(
    '/scans',
    apiKeyAuth('scans:write'),
    ingestLimiter,
    express.json({ limit: '1mb' }),
    validate({ body: ingestScanBody }),
    async (req, res) => {
      const { scan, summary, events } = await ingestScan(req.body, req.apiKey!.id);
      res.status(201).json({ id: scan.id, summary, criticalEvents: events.length });
    },
  );

  return router;
}

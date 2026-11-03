import { Router } from 'express';
import { prisma } from '../../db/prisma.js';

export const healthRouter = Router();

// Liveness: "the process is up". Used by Docker/Kubernetes health checks.
healthRouter.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
});

// Readiness: "the process can actually serve traffic", i.e. the database answers.
// A load balancer should stop sending requests while this fails.
healthRouter.get('/ready', async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ready' });
  } catch {
    res.status(503).json({ status: 'unavailable' });
  }
});

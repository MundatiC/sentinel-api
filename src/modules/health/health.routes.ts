import { Router } from 'express';

export const healthRouter = Router();

// Liveness: "the process is up". Used by Docker/Kubernetes health checks.
// (A /ready endpoint that also checks the database arrives in step 2.)
healthRouter.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
});

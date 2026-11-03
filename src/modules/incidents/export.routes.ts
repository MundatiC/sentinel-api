import { Router } from 'express';
import type { z } from 'zod';
import { apiKeyAuth } from '../../middleware/apiKeyAuth.js';
import { validate } from '../../middleware/validate.js';
import { idParams } from './incidents.schemas.js';
import { getIncidentDetail } from './incidents.service.js';

// Machine-readable export used by the scanner's post-mortem generator. It is separate from the
// dashboard routes because API keys deliberately cannot call user endpoints. A key needs the
// narrow `incidents:read` scope, and this is the only thing that scope allows.
export function createExportRouter() {
  const router = Router();
  router.get(
    '/incidents/:id',
    apiKeyAuth('incidents:read'),
    validate({ params: idParams }),
    async (_req, res) => {
      const { id } = res.locals.params as z.infer<typeof idParams>;
      res.json({ incident: await getIncidentDetail(id) });
    },
  );
  return router;
}

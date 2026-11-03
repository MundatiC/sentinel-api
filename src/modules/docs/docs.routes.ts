import express, { Router } from 'express';
import helmet from 'helmet';
import swaggerUiDist from 'swagger-ui-dist';
import { createOpenApiDocument } from '../../lib/openapi.js';

// Swagger UI is served from our OWN package files (not a CDN), so the page loads no third-party
// code and the CSP below can stay on 'self'.
export function createDocsRouter() {
  const router = Router();
  const document = createOpenApiDocument();

  router.get('/api/v1/openapi.json', (_req, res) => {
    res.json(document);
  });

  // Swagger UI needs inline styles, so /docs gets a slightly looser CSP than the JSON API.
  // This helmet() call REPLACES the strict header set earlier, for these routes only.
  const docsHeaders = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        fontSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    frameguard: { action: 'deny' },
  });

  router.use(
    '/docs/assets',
    docsHeaders,
    express.static(swaggerUiDist.getAbsoluteFSPath(), { index: false }),
  );

  router.get('/docs', docsHeaders, (_req, res) => {
    res.type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Sentinel API docs</title>
    <link rel="stylesheet" href="/docs/assets/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="/docs/assets/swagger-ui-bundle.js"></script>
    <script src="/docs/init.js"></script>
  </body>
</html>`);
  });

  // The init code is a separate file (not an inline <script>) because our CSP forbids inline scripts.
  router.get('/docs/init.js', docsHeaders, (_req, res) => {
    res
      .type('application/javascript')
      .send(
        "window.ui = SwaggerUIBundle({ url: '/api/v1/openapi.json', dom_id: '#swagger-ui', deepLinking: true, persistAuthorization: false });",
      );
  });

  return router;
}

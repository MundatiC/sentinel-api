# sentinel-api

Backend for **Sentinel**, a self-hostable security monitoring platform. It ingests security events and scan results,
raises alerts from threshold rules, tracks incidents, and streams alerts live to the dashboard.

Part of the Sentinel suite:
[sentinel-api](https://github.com/MundatiC/sentinel-api) ·
[sentinel-dashboard](https://github.com/MundatiC/sentinel-dashboard) ·
[sentinel-scanner](https://github.com/MundatiC/sentinel-scanner)

**Stack:** Node.js 22, TypeScript, Express 5, PostgreSQL, Prisma, zod, argon2, JWT, Vitest + supertest.

## Architecture

```mermaid
flowchart LR
  S[sentinel-scanner<br/>Python CLI] -- "X-API-Key<br/>POST /ingest/scans, /ingest/events" --> A
  D[sentinel-dashboard<br/>Next.js] -- "JWT + refresh cookie<br/>REST + SSE" --> A
  subgraph A [sentinel-api]
    direction TB
    R[Routes<br/>auth, validate, rate limit] --> SV[Services]
    SV --> E[Rules engine]
    E --> BUS((alertBus))
    BUS --> SSE[GET /alerts/stream]
  end
  SV --> P[(PostgreSQL)]
  E --> P
```

How an alert is born:

```mermaid
sequenceDiagram
  participant Src as Scanner / log shipper
  participant API as Ingest route
  participant DB as PostgreSQL
  participant Eng as Rules engine
  participant UI as Dashboard (SSE)
  Src->>API: POST /ingest/events (X-API-Key)
  API->>API: authenticate key, rate limit, validate (zod)
  API->>DB: store events
  API->>Eng: evaluate touched (rule, group) pairs
  Eng->>DB: count events in window, create/update alert
  Eng-->>UI: alert.created / alert.updated
```

## Quick start

Requires Node.js 22+ and Docker (for PostgreSQL).

```bash
cp .env.example .env            # set JWT_ACCESS_SECRET (openssl rand -base64 48) and SEED_ADMIN_*
npm install
docker compose up -d db         # PostgreSQL only
npm run db:deploy               # apply migrations
npm run db:seed                 # first admin + default alert rules
npm run dev                     # http://localhost:4000/api/v1/health  ·  docs: http://localhost:4000/docs
```

Try the whole flow:

```bash
# 1. log in
curl -s -c jar -X POST localhost:4000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"<SEED_ADMIN_PASSWORD>"}'        # -> accessToken

# 2. create an API key (the raw key is shown once)
curl -s -X POST localhost:4000/api/v1/api-keys -H "Authorization: Bearer <accessToken>" \
  -H 'content-type: application/json' -d '{"name":"demo","scopes":["events:write"]}'   # -> key

# 3. send 5 failed-login events from one IP: the brute-force rule raises an alert
for i in 1 2 3 4 5; do curl -s -X POST localhost:4000/api/v1/ingest/events -H "X-API-Key: <key>" \
  -H 'content-type: application/json' \
  -d '{"events":[{"type":"auth.login_failed","source":"web-1","ip":"203.0.113.7","message":"Failed login"}]}'; done

# 4. watch alerts live in another terminal
curl -N localhost:4000/api/v1/alerts/stream -H "Authorization: Bearer <accessToken>"
```

Run everything in containers (API + database): `docker compose up --build`.
Run the **whole platform** (needs the three repos side by side): `docker compose -f docker-compose.full.yml up --build`.

## Scripts

| Command                | What it does                                     |
| ---------------------- | ------------------------------------------------ |
| `npm run dev`          | Start with auto-reload                           |
| `npm test`             | Vitest + supertest (needs PostgreSQL, see below) |
| `npm run lint`         | ESLint                                           |
| `npm run typecheck`    | TypeScript without emitting                      |
| `npm run build`        | Compile to `dist/`                               |
| `npm run db:deploy`    | Apply migrations                                 |
| `npm run db:seed`      | Create first admin and default rules             |
| `npm run db:seed:demo` | Demo data for screenshots (see below)            |

**Demo data.** An empty dashboard makes poor screenshots, so `db:seed:demo` adds realistic events, alerts in every
status, one incident with a timeline, and scan history that improves over time. It is safe next to real data: events
carry `metadata.demo`, scans use the reserved domain `*.demo.example`, IPs come from the documentation ranges (RFC 5737),
and the demo analyst account has a random password nobody knows. Re-running refreshes the timestamps.

```bash
# with the full compose stack running (from this folder)
docker compose -f docker-compose.full.yml run --build --rm seed node dist/scripts/seed-demo.js --confirm
docker compose -f docker-compose.full.yml run --rm seed node dist/scripts/seed-demo.js --reset   # removes only the demo data
```

**Tests** use a real PostgreSQL database (default `postgresql://sentinel:sentinel@localhost:5432/sentinel_test`,
override with `TEST_DATABASE_URL`) because mocks hide constraint bugs. **They wipe that database**: never point it at real data.

```bash
DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel_test npm run db:deploy   # once
npm test
```

## API overview

Interactive docs: **`/docs`** (Swagger UI), spec: `/api/v1/openapi.json`. Both are generated from the same zod schemas that
validate requests, and are off in production unless `ENABLE_DOCS=true`. Roles are cumulative: **admin > analyst > viewer**.

| Area      | Endpoints                                                                                  | Access                                  |
| --------- | ------------------------------------------------------------------------------------------ | --------------------------------------- |
| Health    | `GET /health`, `GET /ready`                                                                | public                                  |
| Auth      | `POST /auth/register` (off by default), `login`, `refresh`, `logout`, `GET /auth/me`       | public / cookie / viewer                |
| Users     | `GET /users`, `PATCH /users/:id`                                                           | admin                                   |
| API keys  | `GET/POST /api-keys`, `DELETE /api-keys/:id`                                               | admin                                   |
| Ingest    | `POST /ingest/events`, `POST /ingest/scans`                                                | API key (`events:write`, `scans:write`) |
| Events    | `GET /events`, `/events/:id`, `/events/stats`                                              | viewer                                  |
| Rules     | `GET /alert-rules`; `POST/PATCH/DELETE`                                                    | viewer; admin                           |
| Alerts    | `GET /alerts`, `/alerts/:id`, `/alerts/stream` (SSE); `PATCH /alerts/:id`                  | viewer; analyst                         |
| Incidents | `GET /incidents`, `/incidents/:id`; `POST/PATCH`, `POST /:id/timeline`, `POST /:id/alerts` | viewer; analyst                         |
| Scans     | `GET /scans`, `/scans/:id`                                                                 | viewer                                  |
| Export    | `GET /export/incidents/:id` (for the scanner's post-mortem)                                | API key (`incidents:read`)              |
| Audit     | `GET /audit-logs`                                                                          | admin                                   |

Lists return `{ data, pagination: { page, pageSize, total, totalPages } }` (offset pagination, `pageSize` max 100).
Errors always look like `{ error: { code, message, details?, requestId } }`.

## Project structure

```
src/
  app.ts, server.ts        app factory (testable, no listen) and process entry
  config/env.ts            zod-validated environment: fails fast on bad config
  lib/                     errors, logger, jwt, crypto, password, apiKey, pagination, openapi
  middleware/              authenticate, requireRole, apiKeyAuth, validate, rateLimiters, errorHandler, requestId
  modules/<feature>/       *.routes.ts (HTTP), *.service.ts (logic), *.schemas.ts (zod)
    auth, users, apiKeys, ingest, events, rules, alerts (engine, bus, sse), incidents, scans, audit, docs, health
prisma/                    schema.prisma + migrations (incl. hand-written partial index and audit trigger)
tests/                     unit/ (no DB) and integration/ (supertest + real PostgreSQL)
```

## Design decisions

- **Express + services, not NestJS:** fewer concepts; routes handle HTTP, services hold logic and know nothing about Express.
- **Rules engine runs inside the ingest request** and evaluates per (rule, group), so a burst produces one alert. Failures never lose the ingested data.
- **One active alert per rule+key**, enforced by a PostgreSQL partial unique index, so concurrent requests cannot create duplicates.
- **SSE instead of WebSocket:** alerts only flow server → client; it is plain HTTP and proxy friendly.
- **Self-monitoring:** failed logins to Sentinel itself become events, so the brute-force rule protects the API too.
- **Scaling path:** the in-memory rate limiter and `alertBus` suit one instance. For several, use a Redis rate-limit store and Postgres `LISTEN/NOTIFY` or Redis pub/sub, and move rule evaluation to a queue.

## Security

See [SECURITY.md](SECURITY.md) (reporting + deployment checklist) and [THREAT_MODEL.md](THREAT_MODEL.md)
(STRIDE analysis, OWASP Top 10 2025 mapping, residual risks). Highlights: argon2id, rotating refresh tokens with
theft detection, hashed API keys with scopes, strict input validation, rate limits, append-only audit log, strict CSP.

The approved plan for all three repositories is in [docs/PLAN.md](docs/PLAN.md).

## Screenshots

Interactive API docs at `/docs` (OpenAPI 3.1):

![Swagger UI with the Sentinel API endpoint groups](docs/images/swagger-docs.jpg)

Five failed logins from one IP in, one alert out:

![Ingesting five failed-login events with curl](docs/images/ingest-curl.svg)

What the API feeds in [sentinel-dashboard](https://github.com/MundatiC/sentinel-dashboard): the live alert feed and an incident timeline.

![Dashboard alert feed](docs/images/dashboard-alerts.jpg)
![Dashboard incident timeline](docs/images/dashboard-incident.jpg)

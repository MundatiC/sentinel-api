# Sentinel: approved project plan

Sentinel is a self-hostable security monitoring platform made of three repos:
**sentinel-api** (this repo), **sentinel-dashboard** (Next.js) and **sentinel-scanner** (Python CLI).
This file is the source of truth for decisions made before coding. Update it when a decision changes.

## Cross-repo contract

- The API's `openapi.json` is the single source of truth. The dashboard generates TypeScript types from it;
  the scanner mirrors the ingest payloads as pydantic models.
- Event types shared by all repos: `auth.login_failed`, `auth.login_success`, `http.injection_attempt`,
  `scan.finding_critical`.
- Severity is always `INFO | LOW | MEDIUM | HIGH | CRITICAL`.
- `docker-compose.full.yml` lives in this repo and assumes the three repos are cloned side by side.
- Build order: API (5 steps) → scanner (5) → dashboard (5).

## sentinel-api

### Tech choices

| Concern     | Choice                                                       | Why                                                                                                              |
| ----------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| Framework   | Express 5 + TypeScript                                       | Few concepts to learn; structure comes from routes → service per module. Express 5 forwards async errors itself. |
| ORM         | Prisma                                                       | Typed client, versioned migrations, parameterized queries (no SQL injection).                                    |
| Validation  | zod                                                          | One schema gives validation, TS types and OpenAPI docs.                                                          |
| Passwords   | argon2id                                                     | OWASP first choice; memory-hard against GPU cracking.                                                            |
| Tokens      | 15 min JWT access + opaque refresh token                     | Refresh token in httpOnly cookie, hashed in DB, rotated on use, reuse detection by token family.                 |
| Live alerts | SSE                                                          | Alerts only flow server → client; plain HTTP.                                                                    |
| Tests       | Vitest + supertest against real Postgres                     | Mocks hide constraint bugs.                                                                                      |
| Logging     | pino with redaction                                          | Structured logs; secrets never logged.                                                                           |
| Docs        | OpenAPI 3.1 at `/api/v1/openapi.json`, Swagger UI at `/docs` |                                                                                                                  |

### Folder structure

```
src/
  app.ts            builds the Express app (no listen) so tests can import it
  server.ts         listen() + graceful shutdown
  config/env.ts     zod-validated env, fail fast
  db/prisma.ts
  lib/              errors, logger, jwt, crypto, pagination, openapi
  middleware/       requestId, authenticate, requireRole, apiKeyAuth, validate, rateLimiters, errorHandler
  modules/          health, auth, users, apiKeys, ingest, events, rules (+engine), alerts (+alertBus, sse),
                    incidents, scans, audit      -> each: *.routes.ts, *.service.ts, *.schemas.ts
prisma/             schema.prisma, migrations, seed.ts
tests/              helpers, unit (no DB), integration (supertest)
```

Routes hold HTTP details; services hold business logic and DB calls and know nothing about Express.

### Data model (PostgreSQL, UUID ids, timestamptz)

- **User**: email (unique, lowercase), passwordHash, role (ADMIN|ANALYST|VIEWER), isActive, lastLoginAt
- **RefreshToken**: userId, tokenHash (unique), familyId, expiresAt, revokedAt, replacedById, ip, userAgent
- **ApiKey**: name, prefix (unique), keyHash, scopes[] (events:write, scans:write), createdById, lastUsedAt, expiresAt, revokedAt
- **Event**: apiKeyId?, type, severity, source, actor?, ip?, message, metadata jsonb, occurredAt, receivedAt.
  Indexes: (occurredAt DESC), (type, ip, occurredAt), (type, actor, occurredAt), (severity)
- **Scan**: apiKeyId, target, scannerVersion, startedAt, finishedAt, summary jsonb
- **ScanFinding**: scanId, checkId, category (HEADERS|COOKIES|TLS|EXPOSED_FILES|DEPENDENCIES), severity, title,
  description, evidence jsonb, remediation, references[]
- **AlertRule**: name, enabled, eventType, groupBy (IP|ACTOR|SOURCE), threshold, windowSeconds, severity, cooldownSeconds
- **Alert**: ruleId, status (OPEN|ACKNOWLEDGED|RESOLVED), severity, title, groupKey, eventCount, firstEventAt,
  lastEventAt, assigneeId?, acknowledged/resolved by+at, incidentId?.
  Partial unique index on (ruleId, groupKey) WHERE status = 'OPEN' (DB-enforced dedup)
- **AlertEvent**: alertId, eventId
- **Incident**: title, status (OPEN|INVESTIGATING|CONTAINED|RESOLVED), severity, summary, createdById, resolvedAt
- **IncidentTimelineEntry**: incidentId, occurredAt, kind (NOTE|STATUS_CHANGE|ALERT_LINKED), body, authorId?
- **AuditLog** (append-only): actorType (USER|API_KEY|SYSTEM), actorId, action, targetType, targetId, ip, userAgent, metadata

### Endpoints (all under `/api/v1`; roles cumulative: admin ⊃ analyst ⊃ viewer)

| Endpoint                                                                                  | Auth                                      | Purpose                                               |
| ----------------------------------------------------------------------------------------- | ----------------------------------------- | ----------------------------------------------------- |
| `GET /health`, `GET /ready`                                                               | public                                    | Liveness; readiness checks DB                         |
| `POST /auth/register`                                                                     | public, only if `ALLOW_REGISTRATION=true` | Creates a viewer, never an admin                      |
| `POST /auth/login`                                                                        | public, strict rate limit                 | Access token + refresh cookie                         |
| `POST /auth/refresh`, `POST /auth/logout`                                                 | refresh cookie                            | Rotate / revoke family                                |
| `GET /auth/me`                                                                            | viewer                                    | Current user                                          |
| `GET /users`, `PATCH /users/:id`                                                          | admin                                     | List; change role / deactivate (no self-demotion)     |
| `GET/POST/DELETE /api-keys`                                                               | admin                                     | Raw key shown once                                    |
| `POST /ingest/events`                                                                     | API key `events:write`                    | Batch up to 500; runs rules engine                    |
| `POST /ingest/scans`                                                                      | API key `scans:write`                     | Scan + findings; critical findings also become events |
| `GET /events`, `GET /events/:id`, `GET /events/stats`                                     | viewer                                    | Filters, pagination, chart buckets                    |
| `GET /alert-rules`; `POST/PATCH/DELETE`                                                   | viewer; admin                             | Manage rules                                          |
| `GET /alerts`, `GET /alerts/:id`; `PATCH /alerts/:id`                                     | viewer; analyst                           | Ack / resolve / assign                                |
| `GET /alerts/stream`                                                                      | viewer                                    | SSE feed, 25 s heartbeat                              |
| `GET/POST/PATCH /incidents`, `POST /incidents/:id/timeline`, `POST /incidents/:id/alerts` | viewer / analyst                          | Incidents and timeline                                |
| `GET /scans`, `GET /scans/:id`                                                            | viewer                                    | Scan reports                                          |
| `GET /audit-logs`                                                                         | admin                                     | Filter by actor, action, date                         |

Lists: `{ data, pagination: { page, pageSize, total, totalPages } }` (offset pagination).
Errors: `{ error: { code, message, details?, requestId } }`.

### Key mechanisms

- **Login/refresh**: argon2 verify (dummy hash when email unknown to keep timing equal); generic "Invalid credentials";
  refresh cookie `httpOnly; Secure; SameSite=Strict; Path=/api/v1/auth`; presenting an already-revoked refresh token
  revokes the whole family and is audited. The dashboard keeps the access token in memory only.
- **API keys**: `snt_<8 char prefix>_<32 byte secret>`; lookup by prefix, constant-time compare of SHA-256 hash.
- **Rules engine** (inside the ingest request): for each event and each enabled rule of that type, count events in the
  window for the group key; at threshold bump the open alert or create one (respecting cooldown); publish on alertBus → SSE.
  Seeded rules: brute force (5 failed logins/60 s/IP, HIGH), injection attempts (3/300 s/IP, CRITICAL),
  critical scan finding (1, CRITICAL). The API also records its own failed logins as events.
  Scaling path: queue (BullMQ) + Postgres LISTEN/NOTIFY or Redis pub/sub.
- **Rate limits**: global 300/15 min/IP; login 10/15 min per IP+email; ingest 600/min per API key. `TRUST_PROXY` configurable.

### OWASP Top 10 (2025) mapping (preview; full version in THREAT_MODEL.md)

A01 deny-by-default RBAC, scoped API keys · A02 helmet, CORS allowlist, validated env · A03 lockfile, `npm audit`,
Dependabot · A04 argon2id, hashed tokens · A05 zod + Prisma parameterized queries · A06 registration off by default,
refresh reuse detection, DB-enforced dedup · A07 login limiter, generic errors, short tokens · A08 body limits, strict
schemas, audit log · A09 audit log, redacted logs, self-monitoring · A10 central error handler, fail closed.

### Build steps

| #   | Step                                                                                                | Commit                                                                               |
| --- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| 1   | Scaffold, security middleware, tests, Docker, CI                                                    | `chore: scaffold Express + TypeScript API with security middleware, tests and CI`    |
| 2   | Prisma schema + migration, seed, auth, RBAC, login limiter, audit service, users                    | `feat(auth): JWT access + rotating refresh tokens, argon2id, RBAC and audit log`     |
| 3   | API keys, ingest, events list/filters/stats, scans read                                             | `feat(ingest): API-key authenticated event and scan ingestion with filtered queries` |
| 4   | Rules engine, rule CRUD, alerts, SSE, default rules                                                 | `feat(alerts): threshold rules engine with live SSE alert feed`                      |
| 5   | Incidents, audit endpoint, OpenAPI + Swagger UI, README, SECURITY.md, THREAT_MODEL.md, full compose | `docs: OpenAPI, threat model, security policy; feat: incidents timeline`             |

## sentinel-dashboard (summary)

Next.js App Router + TS, Tailwind + shadcn/ui, TanStack Query + Table (manual/server mode), filters in URL search
params, react-hook-form + zod, Recharts, `@microsoft/fetch-event-source` for SSE (sends Authorization header),
next-themes, `openapi-typescript` + `openapi-fetch`. Tests: Vitest + Testing Library + MSW; Playwright + axe.
Auth: access token in memory only; silent refresh via the API's httpOnly cookie; one retry on 401 with a shared refresh
call; role-aware UI is convenience only, the API enforces access; no `dangerouslySetInnerHTML`; strict CSP in
`next.config.ts`. Pages: login, overview, events, alerts (+detail), incidents (+detail), scans (+detail), admin
(users, api-keys, rules, audit). Steps: scaffold+design system → auth → events+overview → alerts/SSE/incidents/scans →
admin+e2e+README.

## sentinel-scanner (summary)

Python 3.11+, Typer, httpx (+respx), pydantic v2, rich, Jinja2, fpdf2, ruff, mypy, pytest.
Defensive guardrails: `--i-own-this` required for `web` scans (exit code 2 otherwise); GET/HEAD only, never sends
payloads; request delay, max concurrency 2, honest User-Agent; exposed-files check stores only status, size and SHA-256
(never content); log analyzer only detects; http/https scheme allowlist. API key only via `SENTINEL_API_KEY` env,
never a CLI argument.
Checks: headers, cookies, TLS, exposed files, dependencies via OSV `/v1/querybatch`.
Commands: `web`, `deps`, `logs`, `postmortem`. Steps: scaffold+guard → web checks → deps → logs+API client →
post-mortem+docs.

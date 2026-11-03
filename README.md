# sentinel-api

Backend for **Sentinel**, a self-hostable security monitoring platform. It ingests security events and scan results,
raises alerts from threshold rules, and streams them live to the dashboard.

> Status: **step 2 of 5** (auth, RBAC, audit log). Ingestion, the rules engine and incidents are added in the next steps.
> The full design is in [docs/PLAN.md](docs/PLAN.md).

Part of the Sentinel suite: [sentinel-api](https://github.com/MundatiC/sentinel-api) ·
[sentinel-dashboard](https://github.com/MundatiC/sentinel-dashboard) · [sentinel-scanner](https://github.com/MundatiC/sentinel-scanner)

## Architecture

```mermaid
flowchart LR
  S[sentinel-scanner<br/>Python CLI] -- "X-API-Key" --> A[sentinel-api<br/>Express + TypeScript]
  D[sentinel-dashboard<br/>Next.js] -- "JWT + refresh cookie, REST + SSE" --> A
  A --> P[(PostgreSQL)]
```

## Quick start

Requires Node.js 22+.

```bash
cp .env.example .env          # then edit JWT_ACCESS_SECRET and the seed admin password
npm install
docker compose up -d db       # PostgreSQL only
npm run db:deploy             # apply migrations
npm run db:seed               # first admin + default alert rules
npm run dev                   # http://localhost:4000/api/v1/health
```

Try it:

```bash
curl -s -c jar -X POST localhost:4000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"<SEED_ADMIN_PASSWORD>"}'
# use the returned accessToken:
curl -s localhost:4000/api/v1/auth/me -H "Authorization: Bearer <accessToken>"
```

Tests need a PostgreSQL database (default `postgresql://sentinel:sentinel@localhost:5432/sentinel_test`,
override with `TEST_DATABASE_URL`). **They wipe that database**, never point it at real data.
Create it once and migrate it:

```bash
DATABASE_URL=postgresql://sentinel:sentinel@localhost:5432/sentinel_test npm run db:deploy
```

With Docker (API + PostgreSQL):

```bash
cp .env.example .env
docker compose up --build
```

## Scripts

| Command             | What it does                |
| ------------------- | --------------------------- |
| `npm run dev`       | Start with auto-reload      |
| `npm test`          | Run Vitest + supertest      |
| `npm run lint`      | ESLint                      |
| `npm run typecheck` | TypeScript without emitting |
| `npm run build`     | Compile to `dist/`          |

## Auth at a glance

| Endpoint                | Notes                                                                       |
| ----------------------- | --------------------------------------------------------------------------- |
| `POST /auth/register`   | Disabled unless `ALLOW_REGISTRATION=true`; always creates a VIEWER          |
| `POST /auth/login`      | Rate limited per IP + email; returns a 15 min access token + refresh cookie |
| `POST /auth/refresh`    | Rotates the refresh token; replaying a used one revokes the whole session   |
| `POST /auth/logout`     | Revokes the session and clears the cookie                                   |
| `GET /auth/me`          | Current user                                                                |
| `GET/PATCH /users`      | Admin only. Cannot change your own role; deactivation ends sessions         |
| `GET /health`, `/ready` | Liveness and readiness (database) probes                                    |

## Security decisions so far

- Passwords are hashed with **argon2id**; unknown-email logins still run a dummy hash so timing does not reveal accounts.
- Refresh tokens are random 256-bit values stored **only as SHA-256 hashes**, in an `httpOnly; SameSite=Strict` cookie scoped to `/api/v1/auth`.
- JWT verification pins `HS256`, and the user is re-loaded from the database per request, so deactivation and role changes apply instantly.
- The audit log is append-only, enforced by a database trigger, and never stores passwords.
- Roles are checked by `requireRole` (deny by default); the whole users router is admin-only.

- Config is validated at startup (zod); the process refuses to start if it is invalid.
- `helmet` with a strict JSON-API CSP (`default-src 'none'`), no `X-Powered-By`.
- CORS allowlist with credentials; a wildcard origin is rejected at startup.
- 100 kb JSON body limit; one error shape; no stack traces or internals in responses.
- Request ids are validated before use, so clients cannot inject into logs; secrets are redacted from logs.
- Docker image runs as a non-root user; secrets come from the environment and are never committed.

## Screenshots

_Added once the dashboard is built._

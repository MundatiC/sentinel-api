# Security Policy

Sentinel is a security monitoring tool, so its own security matters. Thank you for helping keep it safe.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: **Security → Report a vulnerability**
(<https://github.com/MundatiC/sentinel-api/security/advisories/new>).

Include what you found, how to reproduce it, and the impact you expect. You will get an acknowledgement
within **5 working days**. This is a portfolio/self-hosted project maintained by one person, so
there is no bounty, but valid reports are credited (if you wish) once fixed.

**In scope:** this repository's code, its Docker image and its default configuration.
**Out of scope:** findings that need a modified or deliberately misconfigured deployment (for example a
wildcard `TRUST_PROXY`), denial of service by sheer traffic volume, and vulnerabilities in third-party dependencies
with no exploitable path through Sentinel (report those upstream).

Please test only against your own instance, and do not access data that is not yours.

## Supported versions

Only the latest commit on `main` receives security fixes.

## What Sentinel does to protect itself

| Area              | Measure                                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Passwords         | argon2id hashing; 12+ character minimum; equal-cost login (a dummy hash is verified for unknown emails)                                |
| Sessions          | 15 min JWT (HS256 pinned) + rotating refresh token in an `httpOnly; SameSite=Strict` cookie; reuse detection revokes the whole session |
| Access control    | Deny by default; role checked on every route; user re-loaded from the DB on each request so changes apply instantly                    |
| Machine access    | Scoped API keys, stored only as SHA-256 hashes, shown once, revocable, expirable                                                       |
| Input             | Every body, query and parameter validated with zod (strict: unknown fields rejected); parameterized queries only                       |
| Abuse             | Rate limits per IP, per login+email and per API key; body size limits; capped live connections                                         |
| Secrets           | Only from environment variables; startup fails on weak or missing secrets; logs redact tokens, cookies and passwords                   |
| Accountability    | Append-only audit log (enforced by a database trigger) for every privileged action                                                     |
| Transport/headers | helmet with `default-src 'none'`, CORS allowlist, `X-Powered-By` removed                                                               |
| Errors            | One error shape; stack traces and internals never leave the server                                                                     |
| Supply chain      | Lockfile + `npm ci`, `npm audit` in CI, Dependabot, non-root Docker image                                                              |

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis and the mapping to the OWASP Top 10 (2025).

## Hardening checklist for anyone deploying Sentinel

- [ ] Run behind **HTTPS** and keep `COOKIE_SECURE` unset (secure cookies are the default in production).
- [ ] Set a strong `JWT_ACCESS_SECRET` (`openssl rand -base64 48`). Rotating it logs everyone out.
- [ ] Set `TRUST_PROXY` to the **exact** number of proxies in front of the API. Too high lets clients spoof their IP and dodge rate limits.
- [ ] Set `CORS_ORIGINS` to your dashboard's origin only.
- [ ] Change the seeded admin password after first login; remove `SEED_ADMIN_*` from the environment afterwards.
- [ ] Keep `ALLOW_REGISTRATION=false` unless you really want self-service sign-up.
- [ ] Set `ENABLE_DOCS=false` if the API is public (docs are off in production by default).
- [ ] Use a dedicated database role for the API and, optionally, `REVOKE UPDATE, DELETE, TRUNCATE ON "AuditLog"` from it.
- [ ] Do not expose PostgreSQL to the internet. Back up the database, and ship the audit log somewhere the API cannot modify.
- [ ] Give each scanner/log shipper its **own API key** with the smallest scope it needs, and revoke keys you no longer use.
- [ ] Keep dependencies updated (accept the Dependabot PRs).

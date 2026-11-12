# Deploying Sentinel

Sentinel is three repos but one system: **sentinel-api** (Express + PostgreSQL), **sentinel-dashboard**
(Next.js) and **sentinel-scanner** (a CLI that runs wherever you want to scan from). Only the first two
need hosting.

| Option                                                          | Cost          | Best for                                                 |
| --------------------------------------------------------------- | ------------- | -------------------------------------------------------- |
| [A. Docker Compose](#a-docker-compose-local-or-any-docker-host) | $0            | Trying it, demos on your laptop, any machine with Docker |
| [B. Neon + Render + Vercel](#b-free-tier-neon--render--vercel)  | $0, no domain | A live link for your portfolio                           |
| [C. One VPS + Caddy](#c-one-vps--caddy)                         | the VPS       | Always on, no cold starts, one origin                    |

> **Status of this guide.** Option A is what the project is developed and tested with. The same-origin
> proxy that Option B relies on was verified locally (see [What was verified](#what-was-verified)), but
> the hosted steps were written from the providers' documentation and **have not been run end to end**.
> Free-tier limits change often; check the linked pages before relying on a number.

## The one design constraint: cookies

The dashboard keeps the short-lived access token in memory and the long-lived **refresh token in an
`httpOnly; SameSite=Strict` cookie** set by the API. `SameSite=Strict` means the browser only sends that
cookie when the request comes from the **same site** as the API.

- `localhost:3000` and `localhost:4000` are the same site (ports do not matter), so local development works.
- `your-app.vercel.app` and `your-api.onrender.com` are **different sites** (both domains are on the
  public suffix list), so a dashboard that calls the API directly would be logged out on every reload.

Two ways to stay first-party, both supported:

1. **Same-origin proxy (Option B).** Build the dashboard with `NEXT_PUBLIC_API_URL=/` and
   `API_PROXY_TARGET=https://<your-api>`. The browser only ever talks to the dashboard; Next.js forwards
   `/api/v1/*` to the API. No CORS, no cross-site cookies.
2. **One origin in front of both (Option C).** A reverse proxy serves the dashboard on `/` and the API on
   `/api/`.

Do not "fix" this by loosening the cookie to `SameSite=None`: that removes the CSRF protection the
cookie was chosen for.

## A. Docker Compose (local or any Docker host)

```bash
cd sentinel-api
cp .env.example .env     # set JWT_ACCESS_SECRET, SEED_ADMIN_*, POSTGRES_PASSWORD (see below)
docker compose -f docker-compose.full.yml up --build
```

The three repos must sit side by side (`sentinel-api/`, `sentinel-dashboard/`, `sentinel-scanner/`).
Dashboard: http://localhost:3000, API docs: http://localhost:4000/docs.

Generate the random values (one command per value):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

| Variable              | What to put                                                                                    |
| --------------------- | ---------------------------------------------------------------------------------------------- |
| `JWT_ACCESS_SECRET`   | 32+ random characters. Signs access tokens; the API refuses to start with a short one.         |
| `POSTGRES_PASSWORD`   | Random. Postgres stores it in its volume on first start, so changing it later needs `down -v`. |
| `SEED_ADMIN_EMAIL`    | Your login name.                                                                               |
| `SEED_ADMIN_PASSWORD` | 12+ characters you will type at the login page.                                                |

Optional demo data for screenshots: see "Demo data" in the README.

## B. Free tier: Neon + Render + Vercel

Everything here is $0 and needs no domain or card **as far as the providers' pages say** (verify when you
sign up). The trade-off is cold starts, covered at the end.

```mermaid
flowchart LR
  B[Browser] -- "https://app.vercel.app<br/>/ and /api/v1/*" --> V[Vercel: dashboard]
  V -- "rewrite /api/v1/*" --> R[Render: API container]
  R --> N[(Neon: PostgreSQL)]
  S[Scanner CLI] -- "X-API-Key" --> R
```

### 1. Database: Neon

1. Create a Neon project (free plan) and a database.
2. Copy the **direct** connection string (not the "pooled" one: migrations use advisory locks that
   connection poolers can break). It looks like
   `postgresql://user:pass@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require`.
3. If the API cannot connect and the string contains `channel_binding=require`, remove that parameter.

Neon's free plan has no expiry; compute suspends after 5 idle minutes and wakes on the next query in a
fraction of a second ([pricing](https://neon.com/pricing)).

> **Do not use Render's free Postgres.** It expires 30 days after creation and is deleted 14 days later
> ([Render free tier](https://render.com/docs/free)).

### 2. API: Render

1. New > **Web Service** > public GitHub repo `MundatiC/sentinel-api` (or your fork) > **Docker** runtime.
   The Dockerfile applies migrations on start (`prisma migrate deploy`) and then starts the server.
2. Instance type **Free**. Health check path: `/api/v1/health`.
3. Environment variables:

   | Variable              | Value                                                                                |
   | --------------------- | ------------------------------------------------------------------------------------ |
   | `NODE_ENV`            | `production`                                                                         |
   | `DATABASE_URL`        | the Neon direct string                                                               |
   | `JWT_ACCESS_SECRET`   | 32+ random characters (never reuse your local one)                                   |
   | `ALLOW_REGISTRATION`  | `false`                                                                              |
   | `ENABLE_DOCS`         | `true` if you want a public `/docs` page, otherwise leave unset                      |
   | `CORS_ORIGINS`        | `https://<your-dashboard>.vercel.app` (not used in proxy mode, but keep it explicit) |
   | `TRUST_PROXY`         | `3` (Render's load balancer chain; see "Client IPs" below)                           |
   | `PROXY_SHARED_SECRET` | 32+ random characters; the **same** value goes in Vercel (see step 3)                |

   `PORT` is set by Render and the API reads it. Cookies get the `Secure` flag automatically in production.

4. **Check client IPs.** Rate limits and the audit log use the client IP, so it has to be right.
   See [Client IPs](#client-ips-behind-vercel-and-render) below; verify in Admin > Audit Log after your first login.
5. **Create the admin and default rules.** The free plan has no shell, so run the seed from your own
   machine against Neon (the credentials stay in your shell, never in git):

   ```bash
   cd sentinel-api && npm ci
   DATABASE_URL='<neon direct string>' SEED_ADMIN_EMAIL='you@example.com' \
     SEED_ADMIN_PASSWORD='<12+ chars>' npm run db:seed
   ```

   For a portfolio demo you can also load demo data the same way (`... npm run db:seed:demo -- --confirm`).
   It is clearly separated from real data and `--reset` removes only it. Do not use it on a database that
   holds real security data you care about.

### 3. Dashboard: Vercel

1. Import `MundatiC/sentinel-dashboard` (Hobby plan is for non-commercial use).
2. Environment variables (both are read at **build** time; after changing them, redeploy):

   | Variable              | Value                                                                               |
   | --------------------- | ----------------------------------------------------------------------------------- |
   | `NEXT_PUBLIC_API_URL` | `/`                                                                                 |
   | `API_PROXY_TARGET`    | `https://<your-api>.onrender.com` (origin only)                                     |
   | `PROXY_SHARED_SECRET` | the same 32+ character value as on Render (read at runtime; redeploy after setting) |

3. Deploy, open the site, sign in with the seeded admin.

Vercel's proxy forwards `x-forwarded-for` and `x-real-ip`, and honours upstream `Cache-Control` on external
rewrites by default. That is why the API sends `Cache-Control: no-store` on every response and the
dashboard marks proxied paths uncacheable.

### 4. Verify (do all of these)

- `https://<dashboard>/api/v1/health` returns `{"status":"ok"}`: the proxy works.
- Sign in, reload the page: you stay signed in (the refresh cookie is first-party).
- The **Live** indicator in the top bar stays green for several minutes. This is the one thing that
  depends on Vercel's proxy keeping a long-lived stream open, which the Vercel docs do not state and
  this guide could not test. **If the feed keeps disconnecting**, host the dashboard on Render as a
  second Docker web service instead (same two environment variables as build args). A Node-hosted Next
  server was verified to keep a 75-second stream open (below).
- Create an API key (Admin > API Keys) and run a scan from your machine:

  ```bash
  export SENTINEL_API_URL=https://<your-api>.onrender.com
  export SENTINEL_API_KEY=snt_...
  sentinel-scan web https://your-own-site.example/ --i-own-this --send
  ```

### Client IPs behind Vercel and Render

Rate limits and the audit log key on the client IP. Two things make that hard here:

- Express's `TRUST_PROXY=<n>` means "trust the last n hops of `X-Forwarded-For`". Express's own docs warn it is
  only safe when there are **no multiple, different-length paths** to the app. Here there are two: visitors
  through the dashboard proxy (one extra hop: Vercel) and clients calling the API's URL directly (the scanner,
  curl). A value that credits dashboard visitors correctly lets a direct caller forge their IP, and with it dodge
  the IP-based login limit.
- Vercel overwrites `X-Forwarded-For` with the real visitor IP on its edge, which makes it a trustworthy source
  for the dashboard, but Render sees Vercel's outbound address, not the visitor's.

So the two are combined:

1. `TRUST_PROXY` is set to the hops that **every** route shares (Render's own chain). Observed for a visitor going
   through the dashboard on Render: `2` records a Cloudflare edge address, `3` Vercel's outbound address, `4` the
   visitor. A direct caller has one hop fewer, so `3` should give their real address: use `3` and confirm with the
   checks below.
2. The dashboard's proxy sends the visitor IP it got from Vercel in `X-Sentinel-Client-IP`, with
   `X-Sentinel-Proxy-Secret`. The API only honours that header when the secret matches
   (`PROXY_SHARED_SECRET`, compared in constant time), so a forged header from a direct caller is ignored.

Verify (all with fake credentials, from a machine whose public IP you know; the audit log is Admin > Audit Log):

- Sign in or fail a login **through the dashboard**: the audit IP is your public IP.
- `curl` a failed login **directly at the API**: the audit IP is your public IP.
- The same `curl` with `-H 'X-Forwarded-For: 198.51.100.77'` and with `-H 'X-Sentinel-Client-IP: 198.51.100.77'`
  must **not** record `198.51.100.77`.

If you skip `PROXY_SHARED_SECRET`, the API still works; it just records whichever address `TRUST_PROXY` yields.

### Cold starts and limits

| Piece              | Behaviour on the free tier                                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Render web service | Sleeps after 15 minutes without traffic; the next request takes about a minute. 750 free instance-hours a month: one always-awake service (744 h) fits, two do not. |
| Neon               | Suspends after 5 idle minutes; wakes in well under a second.                                                                                                        |
| Vercel             | No cold start for the static/SSR dashboard.                                                                                                                         |

For a portfolio link, keep the API awake with a free uptime monitor (UptimeRobot, cron-job.org) pinging
`/api/v1/health` every 10 minutes. Otherwise warn visitors in your README that the first load can take a minute.

## C. One VPS + Caddy

Any small VPS with Docker works (for example Oracle Cloud's Always Free ARM instance, which needs a card
to sign up). Run the compose stack, then put Caddy in front so the dashboard and API share one origin
and one TLS certificate:

```caddyfile
sentinel.example.com {
	handle /api/* {
		reverse_proxy api:4000 {
			flush_interval -1   # do not buffer the live alert stream (SSE)
		}
	}
	handle {
		reverse_proxy dashboard:3000
	}
}
```

Build the dashboard with `NEXT_PUBLIC_API_URL=https://sentinel.example.com`, set the API's
`CORS_ORIGINS=https://sentinel.example.com`, remove `COOKIE_SECURE: 'false'` from the compose file, and
publish only ports 80 and 443 (the API and database stay on the internal network). Set `TRUST_PROXY=1`.

## Production checklist

- [ ] `JWT_ACCESS_SECRET`, database and admin passwords are unique to this deployment and stored only in
      the host's secret settings, never in git.
- [ ] `ALLOW_REGISTRATION=false`; the first admin comes from the seed.
- [ ] HTTPS everywhere (both hosts provide it); cookies are `Secure`.
- [ ] `ENABLE_DOCS` is off unless you want a public API reference.
- [ ] The database is not reachable from the internet except through the host's own connection string.
- [ ] You scan only systems you own or have written permission to test.
- [ ] You know how to rotate secrets: change `JWT_ACCESS_SECRET` (signs everyone out), revoke API keys
      from the dashboard, then redeploy.

## What was verified

For the same-origin proxy (dashboard PR "optional same-origin API proxy"), a production build of the
dashboard in proxy mode, run on Node against a stub upstream, showed:

- `/api/v1/health` through the dashboard returned the upstream response and its `Cache-Control: no-store`
- a `Set-Cookie` with `Path=/api/v1/auth; HttpOnly; SameSite=Strict` passed through unchanged
- the CSP was `connect-src 'self'` (no invalid `/` source)
- a 75-second event stream with a heartbeat every 25 seconds stayed open for the whole 75 seconds

Not verified: Vercel's own proxy (streaming behaviour and limits), Render, Neon, and Caddy. The
verification steps above exist for exactly that reason.

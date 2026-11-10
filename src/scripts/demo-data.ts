// Demo data for the dashboard. The CLI is in seed-demo.ts; this file has no side effects on import.
// Fills the dashboard with realistic demo data (events, alerts, an incident, scan history) so
// screenshots and demos are not empty.
//
//   node dist/scripts/seed-demo.js --confirm    create (or refresh) the demo data
//   node dist/scripts/seed-demo.js --reset      remove ONLY the demo data
//
// Safe next to real data: everything it creates is recognisable and --reset deletes nothing else.
//   events    metadata.demo = true
//   scans     target on the reserved domain *.demo.example (RFC 2606, can never be a real site)
//   alerts    the ones linked to demo events
//   incident  created by the demo analyst user (who cannot log in: random unusable password)
// IP addresses come from the documentation ranges (RFC 5737), which are never routed.
import { randomBytes, randomUUID } from 'node:crypto';
import type { ScanCategory, Severity } from '@prisma/client';
import { prisma } from '../db/prisma.js';
import { hashPassword } from '../lib/password.js';
import { defaultRules } from '../modules/rules/defaultRules.js';

const DEMO_DOMAIN = '.demo.example';
const ANALYST_EMAIL = 'analyst@demo.sentinel.example';
const MIN = 60_000;
const DAY = 24 * 60 * MIN;

const isDemoEvent = { metadata: { path: ['demo'], equals: true } };

export async function resetDemo() {
  const analyst = await prisma.user.findUnique({ where: { email: ANALYST_EMAIL } });
  // Order matters: alerts point at incidents and events, so they go first.
  await prisma.alert.deleteMany({ where: { events: { some: { event: isDemoEvent } } } });
  if (analyst) await prisma.incident.deleteMany({ where: { createdById: analyst.id } });
  await prisma.event.deleteMany({ where: isDemoEvent });
  await prisma.scan.deleteMany({ where: { target: { contains: DEMO_DOMAIN } } });
  if (analyst) await prisma.user.delete({ where: { id: analyst.id } });
}

// A tiny deterministic random generator: the demo looks the same every time it is seeded.
function seeded(seed: number) {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------- events and alerts ----------

type DemoEvent = {
  id: string;
  type: string;
  severity: Severity;
  source: string;
  actor: string | null;
  ip: string | null;
  message: string;
  metadata: object;
  occurredAt: Date;
};

let now = Date.now(); // refreshed on every seedDemo() so re-seeding moves the timeline forward

function event(
  type: string,
  severity: Severity,
  source: string,
  ip: string | null,
  actor: string | null,
  message: string,
  minutesAgo: number,
  metadata: object = {},
): DemoEvent {
  return {
    id: randomUUID(),
    type,
    severity,
    source,
    actor,
    ip,
    message,
    metadata: { ...metadata, demo: true },
    occurredAt: new Date(now - minutesAgo * MIN),
  };
}

/** `count` events from one IP, `gapSeconds` apart, the last one `endMinutesAgo` ago. */
function burst(
  count: number,
  endMinutesAgo: number,
  gapSeconds: number,
  make: (i: number, minutesAgo: number) => DemoEvent,
) {
  return Array.from({ length: count }, (_, i) =>
    make(i, endMinutesAgo + ((count - 1 - i) * gapSeconds) / 60),
  );
}

function background(): DemoEvent[] {
  const rand = seeded(7);
  const users = [
    'alice@acme.example',
    'bob@acme.example',
    'carol@acme.example',
    'dev@acme.example',
  ];
  const events: DemoEvent[] = [];
  for (let hour = 0; hour < 24; hour++) {
    // Busier around the middle of the day, quiet at night.
    const hourOfDay = new Date(now - hour * 60 * MIN).getUTCHours();
    const busy = 1 + Math.sin(((hourOfDay - 6) / 24) * Math.PI * 2) * 0.6;
    const successes = Math.round(4 * busy + rand() * 3);
    for (let i = 0; i < successes; i++) {
      const who = users[Math.floor(rand() * users.length)]!;
      events.push(
        event(
          'auth.login_success',
          'INFO',
          'demo-web',
          `192.0.2.${10 + Math.floor(rand() * 40)}`,
          who,
          `Successful login for ${who}`,
          hour * 60 + rand() * 59,
        ),
      );
    }
    if (rand() < 0.55) {
      const ip = `192.0.2.${60 + Math.floor(rand() * 30)}`;
      events.push(
        event(
          'auth.login_failed',
          'LOW',
          'demo-web',
          ip,
          users[Math.floor(rand() * users.length)]!,
          'Failed login (wrong password)',
          hour * 60 + rand() * 59,
        ),
      );
    }
  }
  return events;
}

async function seedActivity(analystId: string) {
  const rules = new Map((await prisma.alertRule.findMany()).map((r) => [r.name, r.id]));
  const ruleId = (name: string) => {
    const id = rules.get(name);
    if (!id) throw new Error(`Default rule missing: ${name}`);
    return id;
  };

  // 1. A brute-force burst, still OPEN
  const bruteForce = burst(9, 190, 7, (_, m) =>
    event(
      'auth.login_failed',
      'MEDIUM',
      'demo-web',
      '203.0.113.42',
      'admin',
      'Failed login for admin',
      m,
    ),
  );
  // 2. SQL-injection probing, acknowledged by the analyst
  const injection = burst(4, 420, 40, (i, m) =>
    event(
      'http.injection_attempt',
      'HIGH',
      'demo-web',
      '198.51.100.7',
      null,
      `Injection pattern in request: /search?q=' OR 1=${i + 1}--`,
      m,
      { path: '/search', pattern: 'sqli' },
    ),
  );
  // 3. An older brute-force that was dealt with
  const oldBrute = burst(6, 1200, 9, (_, m) =>
    event(
      'auth.login_failed',
      'MEDIUM',
      'demo-web',
      '203.0.113.99',
      'support',
      'Failed login for support',
      m,
    ),
  );
  // 4. A critical scan finding on a staging site
  const critical = event(
    'scan.finding_critical',
    'CRITICAL',
    'staging.demo.example',
    null,
    null,
    '.env file exposed on https://staging.demo.example/',
    600,
    { checkId: 'files.env_exposed' },
  );

  const all = [...background(), ...bruteForce, ...injection, ...oldBrute, critical];
  await prisma.event.createMany({
    data: all.map((e) => ({ ...e, receivedAt: e.occurredAt })),
  });

  const first = (evs: DemoEvent[]) => evs[0]!.occurredAt;
  const last = (evs: DemoEvent[]) => evs[evs.length - 1]!.occurredAt;
  const makeAlert = async (
    rule: string,
    key: string,
    severity: Severity,
    evs: DemoEvent[],
    extra: object = {},
  ) => {
    const alert = await prisma.alert.create({
      data: {
        ruleId: ruleId(rule),
        title: `${rule}: ${key}`,
        groupKey: key,
        severity,
        eventCount: evs.length,
        firstEventAt: first(evs),
        lastEventAt: last(evs),
        createdAt: last(evs),
        ...extra,
      },
    });
    await prisma.alertEvent.createMany({
      data: evs.map((e) => ({ alertId: alert.id, eventId: e.id })),
    });
    return alert;
  };

  const alertBrute = await makeAlert(
    'Brute-force login attempts',
    '203.0.113.42',
    'HIGH',
    bruteForce,
  );
  const alertInjection = await makeAlert(
    'Injection attempts',
    '198.51.100.7',
    'CRITICAL',
    injection,
    {
      status: 'ACKNOWLEDGED',
      assigneeId: analystId,
      acknowledgedAt: new Date(now - 400 * MIN),
      acknowledgedById: analystId,
    },
  );
  await makeAlert('Brute-force login attempts', '203.0.113.99', 'HIGH', oldBrute, {
    status: 'RESOLVED',
    resolvedAt: new Date(now - 1150 * MIN),
    resolvedById: analystId,
  });
  await makeAlert('Critical scan finding', 'staging.demo.example', 'CRITICAL', [critical]);

  // The incident that ties the two live attacks together, with a realistic timeline.
  const at = (minutesAgo: number) => new Date(now - minutesAgo * MIN);
  const incident = await prisma.incident.create({
    data: {
      title: 'Credential stuffing and SQL injection probing against the web app',
      status: 'INVESTIGATING',
      severity: 'HIGH',
      summary:
        'Two source IPs attacked the login form and the search endpoint within hours of each other. ' +
        'No successful logins from either IP so far; checking whether the activity is related.',
      createdById: analystId,
      createdAt: at(380),
    },
  });
  await prisma.alert.updateMany({
    where: { id: { in: [alertBrute.id, alertInjection.id] } },
    data: { incidentId: incident.id },
  });
  await prisma.incidentTimelineEntry.createMany({
    data: [
      { kind: 'STATUS_CHANGE' as const, body: 'Incident opened', occurredAt: at(380) },
      {
        kind: 'ALERT_LINKED' as const,
        body: `Alert linked: ${alertInjection.title}`,
        occurredAt: at(378),
      },
      {
        kind: 'NOTE' as const,
        body: 'The payloads are classic tautologies against /search. The ORM is parameterised, so this looks like automated scanning, not a targeted attack.',
        occurredAt: at(360),
      },
      {
        kind: 'STATUS_CHANGE' as const,
        body: 'Status changed from OPEN to INVESTIGATING',
        occurredAt: at(355),
      },
      {
        kind: 'ALERT_LINKED' as const,
        body: `Alert linked: ${alertBrute.title}`,
        occurredAt: at(185),
      },
      {
        kind: 'NOTE' as const,
        body: 'Blocked 203.0.113.42 at the edge. Checked the auth log: no successful login from it, and the targeted account (admin) has MFA.',
        occurredAt: at(170),
      },
    ].map((entry) => ({ ...entry, incidentId: incident.id, authorId: analystId })),
  });
}

// ---------- scans ----------

type Template = {
  category: ScanCategory;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  references: string[];
};

const MDN = 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/';
const OWASP_HEADERS = 'https://owasp.org/www-project-secure-headers/';

const CATALOG: Record<string, Template> = {
  'files.git_exposed': {
    category: 'EXPOSED_FILES',
    severity: 'CRITICAL',
    title: '.git directory is publicly readable',
    description:
      'The repository metadata is served by the web server, so anyone can download the full source code and its history, including any secrets ever committed.',
    remediation:
      'Block access to /.git (deny rule in the web server) and rotate any secrets that were in the repository.',
    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
  },
  'files.env_exposed': {
    category: 'EXPOSED_FILES',
    severity: 'CRITICAL',
    title: '.env file is publicly readable',
    description:
      'A .env file is served over HTTP. These files normally hold database passwords and API keys. (The scanner stored only the status code and a hash, never the content.)',
    remediation:
      'Remove the file from the web root, deny dotfiles in the web server, and rotate every secret it contained.',
    references: ['https://12factor.net/config'],
  },
  'headers.csp_missing': {
    category: 'HEADERS',
    severity: 'MEDIUM',
    title: 'Content-Security-Policy header is missing',
    description:
      'Without a CSP the browser will run any script injected into a page (XSS), so a single injection bug becomes much more damaging.',
    remediation:
      "Send a Content-Security-Policy, starting strict (default-src 'self') and loosening only as needed.",
    references: [MDN + 'Content-Security-Policy', OWASP_HEADERS],
  },
  'headers.hsts_missing': {
    category: 'HEADERS',
    severity: 'MEDIUM',
    title: 'Strict-Transport-Security (HSTS) header is missing',
    description:
      'Without HSTS a browser can be tricked into using plain HTTP on first contact, exposing the session to a network attacker.',
    remediation:
      'Send Strict-Transport-Security: max-age=31536000; includeSubDomains once HTTPS works everywhere.',
    references: [MDN + 'Strict-Transport-Security'],
  },
  'headers.clickjacking': {
    category: 'HEADERS',
    severity: 'MEDIUM',
    title: 'Page can be embedded in other sites (clickjacking)',
    description:
      'Neither X-Frame-Options nor a CSP frame-ancestors directive is set, so another site can frame this page and trick users into clicking on it.',
    remediation:
      "Send Content-Security-Policy: frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY.",
    references: [MDN + 'X-Frame-Options'],
  },
  'headers.nosniff_missing': {
    category: 'HEADERS',
    severity: 'LOW',
    title: 'X-Content-Type-Options: nosniff is missing',
    description:
      "Browsers may guess a file's type and execute content that was served as something harmless.",
    remediation: 'Send X-Content-Type-Options: nosniff on all responses.',
    references: [MDN + 'X-Content-Type-Options'],
  },
  'headers.referrer_policy_missing': {
    category: 'HEADERS',
    severity: 'LOW',
    title: 'Referrer-Policy header is missing',
    description:
      'Full URLs (which can contain tokens or ids) may be sent to other sites when users follow links.',
    remediation: 'Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).',
    references: [MDN + 'Referrer-Policy'],
  },
  'headers.permissions_policy_missing': {
    category: 'HEADERS',
    severity: 'INFO',
    title: 'Permissions-Policy header is missing',
    description:
      'Powerful browser features (camera, microphone, geolocation) are not explicitly restricted.',
    remediation: 'Send a Permissions-Policy that disables features the site does not use.',
    references: [MDN + 'Permissions-Policy'],
  },
  'headers.x_powered_by': {
    category: 'HEADERS',
    severity: 'LOW',
    title: 'X-Powered-By header reveals the technology in use',
    description: 'Advertising the framework and version helps attackers pick known exploits.',
    remediation: "Remove the header (in Express: app.disable('x-powered-by') or use helmet).",
    references: [OWASP_HEADERS],
  },
  'headers.server_version': {
    category: 'HEADERS',
    severity: 'LOW',
    title: 'Server header reveals a software version',
    description: 'The exact server version helps attackers match it to published vulnerabilities.',
    remediation: 'Hide the version (nginx: server_tokens off;).',
    references: [OWASP_HEADERS],
  },
  'cookies.no_httponly': {
    category: 'COOKIES',
    severity: 'MEDIUM',
    title: 'Session cookie is readable by JavaScript (no HttpOnly)',
    description:
      'If an attacker injects a script, it can read this cookie and take over the session.',
    remediation: 'Set the HttpOnly flag on session cookies.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
  },
  'cookies.no_secure': {
    category: 'COOKIES',
    severity: 'MEDIUM',
    title: 'Cookie can be sent over plain HTTP (no Secure flag)',
    description: 'The cookie can leak on any unencrypted request.',
    remediation: 'Set the Secure flag on cookies.',
    references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies'],
  },
  'tls.no_https_redirect': {
    category: 'TLS',
    severity: 'MEDIUM',
    title: 'HTTP does not redirect to HTTPS',
    description:
      'The site is served over plain HTTP with no redirect to HTTPS, so users who type the address without https:// are exposed to eavesdropping.',
    remediation: 'Redirect all HTTP requests to HTTPS (301/308) and enable HSTS.',
    references: [MDN + 'Strict-Transport-Security'],
  },
};

// Each target is scanned several times; later scans have fewer findings, so trends and the
// "fixed since last scan" line have something to show.
const SCANS: { host: string; daysAgo: number; minutesAgo?: number; checks: string[] }[] = [
  {
    host: 'shop',
    daysAgo: 14,
    checks: [
      'files.git_exposed',
      'headers.csp_missing',
      'headers.hsts_missing',
      'headers.clickjacking',
      'cookies.no_httponly',
      'cookies.no_secure',
      'tls.no_https_redirect',
      'headers.nosniff_missing',
      'headers.referrer_policy_missing',
    ],
  },
  {
    host: 'shop',
    daysAgo: 8,
    checks: [
      'headers.csp_missing',
      'headers.hsts_missing',
      'headers.clickjacking',
      'cookies.no_httponly',
      'cookies.no_secure',
      'headers.nosniff_missing',
      'headers.referrer_policy_missing',
    ],
  },
  {
    host: 'shop',
    daysAgo: 3,
    checks: [
      'headers.csp_missing',
      'headers.clickjacking',
      'headers.nosniff_missing',
      'headers.referrer_policy_missing',
    ],
  },
  {
    host: 'shop',
    daysAgo: 1,
    checks: ['headers.csp_missing', 'headers.permissions_policy_missing'],
  },
  {
    host: 'api',
    daysAgo: 10,
    checks: [
      'headers.csp_missing',
      'headers.clickjacking',
      'headers.x_powered_by',
      'headers.server_version',
      'headers.nosniff_missing',
      'headers.referrer_policy_missing',
    ],
  },
  { host: 'api', daysAgo: 2, checks: ['headers.permissions_policy_missing'] },
  {
    host: 'blog',
    daysAgo: 3,
    checks: [
      'headers.hsts_missing',
      'headers.csp_missing',
      'headers.referrer_policy_missing',
      'headers.permissions_policy_missing',
    ],
  },
  {
    host: 'staging',
    daysAgo: 0,
    minutesAgo: 600,
    checks: [
      'files.env_exposed',
      'headers.csp_missing',
      'headers.hsts_missing',
      'tls.no_https_redirect',
    ],
  },
];

async function seedScans() {
  for (const scan of SCANS) {
    const finishedAt = new Date(now - scan.daysAgo * DAY - (scan.minutesAgo ?? 0) * MIN);
    const templates = scan.checks.map((checkId) => {
      const t = CATALOG[checkId];
      if (!t) throw new Error(`Unknown demo check: ${checkId}`);
      return { checkId, ...t };
    });
    const summary: Record<string, number> = {};
    for (const t of templates) summary[t.severity] = (summary[t.severity] ?? 0) + 1;
    await prisma.scan.create({
      data: {
        target: `https://${scan.host}${DEMO_DOMAIN}/`,
        scannerVersion: '0.1.0',
        startedAt: new Date(finishedAt.getTime() - 14_000),
        finishedAt,
        createdAt: finishedAt,
        summary,
        findings: { create: templates.map((t) => ({ ...t, evidence: {} })) },
      },
    });
  }
}

/** (Re)creates the demo data. Running it again first removes the old demo data, then adds fresh data. */
export async function seedDemo() {
  now = Date.now();
  await resetDemo(); // re-running refreshes the timestamps instead of piling up duplicates
  for (const rule of defaultRules) {
    await prisma.alertRule.upsert({ where: { name: rule.name }, update: {}, create: rule });
  }
  const analyst = await prisma.user.create({
    data: {
      email: ANALYST_EMAIL,
      // Nobody knows this password, so the demo account can never be logged into.
      passwordHash: await hashPassword(randomBytes(32).toString('hex')),
      role: 'ANALYST',
    },
  });
  await seedActivity(analyst.id);
  await seedScans();
}

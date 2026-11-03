// Creates the first admin (from env vars) and the default alert rules.
// Safe to run repeatedly: everything is an upsert.
import { z } from 'zod';
import { prisma } from '../src/db/prisma.js';
import { hashPassword } from '../src/lib/password.js';

const defaultRules = [
  {
    name: 'Brute-force login attempts',
    description: '5 failed logins from the same IP within 1 minute',
    eventType: 'auth.login_failed',
    groupBy: 'IP',
    threshold: 5,
    windowSeconds: 60,
    severity: 'HIGH',
    cooldownSeconds: 300,
  },
  {
    name: 'Injection attempts',
    description: '3 injection-pattern requests from the same IP within 5 minutes',
    eventType: 'http.injection_attempt',
    groupBy: 'IP',
    threshold: 3,
    windowSeconds: 300,
    severity: 'CRITICAL',
    cooldownSeconds: 600,
  },
  {
    name: 'Critical scan finding',
    description: 'A scan reported a critical finding',
    eventType: 'scan.finding_critical',
    groupBy: 'SOURCE',
    threshold: 1,
    windowSeconds: 60,
    severity: 'CRITICAL',
    cooldownSeconds: 0,
  },
] as const;

async function main() {
  for (const rule of defaultRules) {
    await prisma.alertRule.upsert({ where: { name: rule.name }, update: {}, create: rule });
  }
  console.log(`Seeded ${defaultRules.length} default alert rules`);

  const email = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;
  if (!email || !password) {
    console.log('SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD not set: skipping admin creation');
    return;
  }
  const parsed = z
    .object({ email: z.email().toLowerCase(), password: z.string().min(12) })
    .parse({ email, password });

  // `update: {}` means re-running the seed never overwrites an existing admin's password.
  await prisma.user.upsert({
    where: { email: parsed.email },
    update: {},
    create: {
      email: parsed.email,
      passwordHash: await hashPassword(parsed.password),
      role: 'ADMIN',
    },
  });
  console.log(`Admin ready: ${parsed.email}`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());

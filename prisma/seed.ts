// Creates the first admin (from env vars) and the default alert rules.
// Safe to run repeatedly: everything is an upsert.
import { z } from 'zod';
import { prisma } from '../src/db/prisma.js';
import { hashPassword } from '../src/lib/password.js';
import { defaultRules } from '../src/modules/rules/defaultRules.js';

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

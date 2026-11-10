// CLI for the demo data. See demo-data.ts for what it creates and how it stays separate from real data.
//
//   node dist/scripts/seed-demo.js --confirm    create (or refresh) the demo data
//   node dist/scripts/seed-demo.js --reset      remove ONLY the demo data
import { prisma } from '../db/prisma.js';
import { resetDemo, seedDemo } from './demo-data.js';

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--reset')) {
    await resetDemo();
    console.log('Demo data removed (nothing else was touched).');
  } else if (args.includes('--confirm')) {
    await seedDemo();
    console.log('Demo data created. Refresh the dashboard. Remove it with --reset.');
  } else {
    console.log(
      'Adds demo events, alerts, an incident and scan history, clearly separated from real data.\n' +
        '  --confirm   create (or refresh) the demo data\n' +
        '  --reset     remove only the demo data',
    );
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());

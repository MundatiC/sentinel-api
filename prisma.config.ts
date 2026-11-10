import 'dotenv/config';
import { defineConfig, env } from 'prisma/config';

// Prisma 7 reads the connection URL here (not in schema.prisma) for migrate/validate.
export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: { url: env('DATABASE_URL') },
});

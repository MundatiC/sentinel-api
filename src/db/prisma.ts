import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';

// One shared client for the whole process. Prisma 7 talks to Postgres through a
// driver adapter, which owns the connection pool and reads DATABASE_URL.
export const prisma = new PrismaClient({
  adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL }),
});

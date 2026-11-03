import { PrismaClient } from '@prisma/client';

// One shared client for the whole process (it manages its own connection pool).
// It reads DATABASE_URL from the environment.
export const prisma = new PrismaClient();

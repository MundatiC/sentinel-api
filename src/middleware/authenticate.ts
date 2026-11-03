import type { Role } from '@prisma/client';
import type { RequestHandler } from 'express';
import { prisma } from '../db/prisma.js';
import type { Env } from '../config/env.js';
import { AppError } from '../lib/errors.js';
import { verifyAccessToken } from '../lib/jwt.js';

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
}

// Adding `req.user` to Express's Request type needs a global namespace augmentation: it is the
// documented way to do it, so the lint rule is disabled for this one line.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

// Reads "Authorization: Bearer <jwt>", verifies it, then loads the user from the database.
// We look the user up on every request (instead of trusting the role inside the token) so that
// deactivating a user or changing their role takes effect IMMEDIATELY, not after the token expires.
export function authenticate(env: Pick<Env, 'JWT_ACCESS_SECRET'>): RequestHandler {
  return async (req, _res, next) => {
    const header = req.get('authorization');
    if (!header?.startsWith('Bearer ')) throw AppError.unauthorized();

    let userId: string;
    try {
      userId = verifyAccessToken(header.slice(7), env.JWT_ACCESS_SECRET).sub;
    } catch {
      throw AppError.unauthorized('Invalid or expired token');
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) throw AppError.unauthorized('Invalid or expired token');

    req.user = { id: user.id, email: user.email, role: user.role };
    next();
  };
}

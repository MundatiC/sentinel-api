import type { Role } from '@prisma/client';
import type { RequestHandler } from 'express';
import { AppError } from '../lib/errors.js';

// Roles are cumulative: an ADMIN can do everything an ANALYST can, and so on.
const RANK: Record<Role, number> = { VIEWER: 1, ANALYST: 2, ADMIN: 3 };

// Must run AFTER authenticate. Deny by default: no user on the request means no access.
export function requireRole(minimum: Role): RequestHandler {
  return (req, _res, next) => {
    if (!req.user) throw AppError.unauthorized();
    if (RANK[req.user.role] < RANK[minimum]) throw AppError.forbidden();
    next();
  };
}

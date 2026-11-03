import type { User } from '@prisma/client';
import { randomUUID } from 'node:crypto';
import type { Env } from '../../config/env.js';
import { prisma } from '../../db/prisma.js';
import { randomToken, sha256 } from '../../lib/crypto.js';
import { AppError } from '../../lib/errors.js';
import { signAccessToken } from '../../lib/jwt.js';
import { getDummyHash, hashPassword, verifyPassword } from '../../lib/password.js';
import { recordAudit } from '../audit/audit.service.js';
import type { LoginBody, RegisterBody } from './auth.schemas.js';

interface Meta {
  ip: string | null;
  userAgent: string | null;
}

// A refresh token that was rotated away less than this long ago is probably a second browser
// tab or a double click racing the first request, NOT a thief. We reject it but do not
// revoke the whole session.
const REUSE_GRACE_MS = 10_000;

export function toPublicUser(user: Pick<User, 'id' | 'email' | 'role' | 'isActive' | 'createdAt'>) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt,
  };
}

async function issueRefreshToken(
  userId: string,
  familyId: string,
  env: Pick<Env, 'REFRESH_TOKEN_TTL_DAYS'>,
  meta: Meta,
) {
  const raw = randomToken(32);
  const record = await prisma.refreshToken.create({
    data: {
      userId,
      familyId,
      tokenHash: sha256(raw), // we store only the hash
      expiresAt: new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 86_400_000),
      ip: meta.ip,
      userAgent: meta.userAgent,
    },
  });
  return { raw, record };
}

export async function register(body: RegisterBody, meta: Meta) {
  const existing = await prisma.user.findUnique({ where: { email: body.email } });
  if (existing) throw new AppError(409, 'EMAIL_TAKEN', 'An account with this email already exists');

  // Self-registered users are ALWAYS viewers. Admins promote people later.
  const user = await prisma.user.create({
    data: { email: body.email, passwordHash: await hashPassword(body.password), role: 'VIEWER' },
  });
  await recordAudit({ actorType: 'USER', actorId: user.id, action: 'auth.register', ...meta });
  return toPublicUser(user);
}

export async function login(
  body: LoginBody,
  env: Pick<Env, 'JWT_ACCESS_SECRET' | 'ACCESS_TOKEN_TTL_MINUTES' | 'REFRESH_TOKEN_TTL_DAYS'>,
  meta: Meta,
) {
  const user = await prisma.user.findUnique({ where: { email: body.email } });

  // Always run one argon2 verification, even when the user does not exist (see password.ts).
  const passwordOk = await verifyPassword(
    user?.passwordHash ?? (await getDummyHash()),
    body.password,
  );

  if (!user || !passwordOk || !user.isActive) {
    await recordAudit({
      actorType: 'USER',
      actorId: user?.id,
      action: 'auth.login_failed',
      // The attempted email is useful for investigations; the password is NEVER recorded.
      metadata: {
        email: body.email,
        reason: !user ? 'unknown_user' : !passwordOk ? 'bad_password' : 'inactive',
      },
      ...meta,
    });
    // One generic message for every failure reason, so the response reveals nothing.
    throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid credentials');
  }

  const { raw } = await issueRefreshToken(user.id, randomUUID(), env, meta);
  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await recordAudit({ actorType: 'USER', actorId: user.id, action: 'auth.login', ...meta });

  return {
    accessToken: signAccessToken(user, env.JWT_ACCESS_SECRET, env.ACCESS_TOKEN_TTL_MINUTES),
    refreshToken: raw,
    user: toPublicUser(user),
  };
}

// Refresh-token ROTATION: every use of a refresh token consumes it and issues a new one.
export async function refresh(
  rawToken: string,
  env: Pick<Env, 'JWT_ACCESS_SECRET' | 'ACCESS_TOKEN_TTL_MINUTES' | 'REFRESH_TOKEN_TTL_DAYS'>,
  meta: Meta,
) {
  const invalid = () => AppError.unauthorized('Invalid or expired session');

  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash: sha256(rawToken) },
    include: { user: true },
  });
  if (!stored) throw invalid();

  // "Claim" the token atomically: this UPDATE only succeeds for the FIRST caller, because it
  // requires revokedAt to still be null. If two requests race, exactly one wins.
  const claimed = await prisma.refreshToken.updateMany({
    where: { id: stored.id, revokedAt: null, expiresAt: { gt: new Date() } },
    data: { revokedAt: new Date() },
  });

  if (claimed.count === 0) {
    // Only a token that was ROTATED away (it has a successor) counts as "reuse". Tokens revoked
    // by logout, deactivation or an earlier theft response are simply dead: reject, nothing more.
    const wasRotated = stored.replacedById !== null;
    const withinGrace =
      stored.revokedAt && Date.now() - stored.revokedAt.getTime() < REUSE_GRACE_MS;
    if (wasRotated && !withinGrace) {
      // A used token is being presented again: it was probably stolen. Kill every token from
      // this login so BOTH the thief and the victim must log in again.
      await prisma.refreshToken.updateMany({
        where: { familyId: stored.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await recordAudit({
        actorType: 'USER',
        actorId: stored.userId,
        action: 'auth.refresh_reuse_detected',
        metadata: { familyId: stored.familyId },
        ...meta,
      });
    }
    throw invalid();
  }

  if (!stored.user.isActive) throw invalid();

  const next = await issueRefreshToken(stored.userId, stored.familyId, env, meta);
  await prisma.refreshToken.update({
    where: { id: stored.id },
    data: { replacedById: next.record.id },
  });

  return {
    accessToken: signAccessToken(stored.user, env.JWT_ACCESS_SECRET, env.ACCESS_TOKEN_TTL_MINUTES),
    refreshToken: next.raw,
    user: toPublicUser(stored.user),
  };
}

export async function logout(rawToken: string | undefined, meta: Meta) {
  if (!rawToken) return;
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash: sha256(rawToken) } });
  if (!stored) return;
  await prisma.refreshToken.updateMany({
    where: { familyId: stored.familyId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  await recordAudit({ actorType: 'USER', actorId: stored.userId, action: 'auth.logout', ...meta });
}

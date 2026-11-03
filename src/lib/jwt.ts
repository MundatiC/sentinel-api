import jwt from 'jsonwebtoken';
import type { Role } from '@prisma/client';

const ISSUER = 'sentinel-api';

export interface AccessTokenPayload {
  sub: string;
  role: Role;
}

export function signAccessToken(
  user: { id: string; role: Role },
  secret: string,
  ttlMinutes: number,
): string {
  return jwt.sign({ role: user.role }, secret, {
    subject: user.id,
    issuer: ISSUER,
    algorithm: 'HS256',
    expiresIn: ttlMinutes * 60,
  });
}

// `algorithms` is pinned on purpose. Without it, a token claiming alg "none" (or switching
// algorithm families) could trick some libraries into skipping signature checks.
export function verifyAccessToken(token: string, secret: string): AccessTokenPayload {
  const payload = jwt.verify(token, secret, { algorithms: ['HS256'], issuer: ISSUER });
  if (typeof payload === 'string' || !payload.sub) throw new Error('Invalid token payload');
  return { sub: payload.sub, role: payload['role'] as Role };
}

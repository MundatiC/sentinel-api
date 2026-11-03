import type { ActorType, Prisma } from '@prisma/client';
import { prisma } from '../../db/prisma.js';

export interface AuditEntry {
  actorType: ActorType;
  actorId?: string | null;
  action: string; // e.g. "auth.login_failed", "user.role_changed"
  targetType?: string;
  targetId?: string;
  ip?: string | null;
  userAgent?: string | null;
  metadata?: Prisma.InputJsonObject;
}

// Every security-relevant action calls this. Rows are append-only (see the DB trigger).
// Never put secrets (passwords, tokens) in `metadata`.
export async function recordAudit(entry: AuditEntry): Promise<void> {
  await prisma.auditLog.create({
    data: {
      actorType: entry.actorType,
      actorId: entry.actorId ?? null,
      action: entry.action,
      targetType: entry.targetType,
      targetId: entry.targetId,
      ip: entry.ip,
      userAgent: entry.userAgent,
      metadata: entry.metadata ?? {},
    },
  });
}

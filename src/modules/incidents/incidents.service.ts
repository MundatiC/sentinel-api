import type { Prisma } from '@prisma/client';
import { prisma } from '../../db/prisma.js';
import { AppError } from '../../lib/errors.js';

type Tx = Prisma.TransactionClient;

// Full incident: details + timeline (oldest first) + linked alerts.
export async function getIncidentDetail(id: string) {
  const incident = await prisma.incident.findUnique({
    where: { id },
    include: {
      timeline: { orderBy: { occurredAt: 'asc' } },
      alerts: { include: { rule: { select: { name: true } } }, orderBy: { createdAt: 'asc' } },
    },
  });
  if (!incident) throw AppError.notFound('Incident not found');

  // Timeline entries store only an authorId; attach the email so the UI can show who wrote it.
  const authorIds = [
    ...new Set(incident.timeline.map((e) => e.authorId).filter((x): x is string => !!x)),
  ];
  const authors = await prisma.user.findMany({
    where: { id: { in: authorIds } },
    select: { id: true, email: true },
  });
  const byId = new Map(authors.map((a) => [a.id, a]));

  return {
    ...incident,
    timeline: incident.timeline.map((entry) => ({
      ...entry,
      author: entry.authorId ? (byId.get(entry.authorId) ?? null) : null,
    })),
    alerts: incident.alerts.map(({ rule, ...alert }) => ({ ...alert, ruleName: rule.name })),
  };
}

// Links an alert to an incident and writes the timeline entry. An alert can belong to only ONE
// incident: silently moving it would rewrite another incident's history.
export async function linkAlert(tx: Tx, incidentId: string, alertId: string, authorId: string) {
  const alert = await tx.alert.findUnique({ where: { id: alertId } });
  if (!alert) throw AppError.badRequest(`Alert ${alertId} does not exist`);
  if (alert.incidentId === incidentId) return false; // already linked: nothing to do
  if (alert.incidentId)
    throw new AppError(409, 'ALERT_ALREADY_LINKED', 'This alert belongs to another incident');
  await tx.alert.update({ where: { id: alertId }, data: { incidentId } });
  await tx.incidentTimelineEntry.create({
    data: { incidentId, kind: 'ALERT_LINKED', body: `Alert linked: ${alert.title}`, authorId },
  });
  return true;
}

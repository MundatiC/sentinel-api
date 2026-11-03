import { Prisma, type Alert, type AlertRule, type Event } from '@prisma/client';
import { prisma } from '../../db/prisma.js';
import { alertBus, type AlertView } from './alertBus.js';

// Which Event column each rule "groups by". "5 failed logins from the SAME ip" = groupBy IP.
const GROUP_FIELD = { IP: 'ip', ACTOR: 'actor', SOURCE: 'source' } as const;
const MAX_EVENTS_PER_WINDOW = 1000;

export function toAlertView(alert: Alert, ruleName: string): AlertView {
  return {
    id: alert.id,
    ruleId: alert.ruleId,
    ruleName,
    status: alert.status,
    severity: alert.severity,
    title: alert.title,
    groupKey: alert.groupKey,
    eventCount: alert.eventCount,
    firstEventAt: alert.firstEventAt,
    lastEventAt: alert.lastEventAt,
    createdAt: alert.createdAt,
  };
}

// Called after new events are stored. For each (rule, group key) touched by the batch it asks:
// "are there at least `threshold` matching events in the last `windowSeconds`?" If yes, it
// raises a new alert, or adds to the one that is already active.
//
// We evaluate per GROUP, not per event: a batch of 5 failed logins must produce one alert,
// not five evaluations that each race to create it.
export async function evaluateEvents(events: Event[]): Promise<void> {
  if (events.length === 0) return;

  const rules = await prisma.alertRule.findMany({
    where: { enabled: true, eventType: { in: [...new Set(events.map((event) => event.type))] } },
  });
  if (rules.length === 0) return;

  const groups = new Map<string, { rule: AlertRule; key: string; latest: Date }>();
  for (const event of events) {
    for (const rule of rules) {
      if (rule.eventType !== event.type) continue;
      const key = event[GROUP_FIELD[rule.groupBy]];
      if (!key) continue; // e.g. an IP-grouped rule cannot use an event that has no IP
      const id = `${rule.id}|${key}`;
      const group = groups.get(id);
      if (!group) groups.set(id, { rule, key, latest: event.occurredAt });
      else if (event.occurredAt > group.latest) group.latest = event.occurredAt;
    }
  }

  for (const { rule, key, latest } of groups.values()) {
    await evaluateGroup(rule, key, latest);
  }
}

async function evaluateGroup(rule: AlertRule, key: string, latest: Date) {
  const windowStart = new Date(latest.getTime() - rule.windowSeconds * 1000);
  const inWindow = await prisma.event.findMany({
    where: {
      type: rule.eventType,
      [GROUP_FIELD[rule.groupBy]]: key,
      occurredAt: { gte: windowStart, lte: latest },
    },
    select: { id: true, occurredAt: true },
    orderBy: { occurredAt: 'desc' },
    take: MAX_EVENTS_PER_WINDOW,
  });
  if (inWindow.length < rule.threshold) return;

  // Two requests can reach the threshold at the same moment. The database has a partial unique
  // index ("one OPEN alert per rule + key"), so if both try to INSERT, one fails with P2002.
  // The loser simply retries and finds the winner's alert, then updates it.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const result = await upsertAlert(rule, key, inWindow);
      if (result) {
        alertBus.publish({
          type: result.created ? 'alert.created' : 'alert.updated',
          alert: toAlertView(result.alert, rule.name),
        });
      }
      return;
    } catch (err) {
      const raceLost = err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
      if (!raceLost || attempt === 1) throw err;
    }
  }
}

async function upsertAlert(
  rule: AlertRule,
  key: string,
  inWindow: { id: string; occurredAt: Date }[],
) {
  const times = inWindow.map((event) => event.occurredAt.getTime());
  const newest = new Date(Math.max(...times));
  const oldest = new Date(Math.min(...times));

  return prisma.$transaction(async (tx) => {
    // An alert that is still OPEN or ACKNOWLEDGED is "active": new events join it instead of
    // creating a duplicate (an analyst who acknowledged it should not be paged again).
    const active = await tx.alert.findFirst({
      where: { ruleId: rule.id, groupKey: key, status: { in: ['OPEN', 'ACKNOWLEDGED'] } },
    });

    let alertId: string;
    let created = false;
    if (active) {
      alertId = active.id;
    } else {
      // Cooldown: after an alert is resolved, stay quiet for a while so a still-running attack
      // does not instantly re-alert.
      if (rule.cooldownSeconds > 0) {
        const last = await tx.alert.findFirst({
          where: { ruleId: rule.id, groupKey: key },
          orderBy: { createdAt: 'desc' },
        });
        const quietUntil =
          last?.resolvedAt && last.resolvedAt.getTime() + rule.cooldownSeconds * 1000;
        if (quietUntil && quietUntil > Date.now()) return null;
      }
      const alert = await tx.alert.create({
        data: {
          ruleId: rule.id,
          severity: rule.severity,
          title: `${rule.name}: ${key}`,
          groupKey: key,
          firstEventAt: oldest,
          lastEventAt: newest,
        },
      });
      alertId = alert.id;
      created = true;
    }

    await tx.alertEvent.createMany({
      data: inWindow.map((event) => ({ alertId, eventId: event.id })),
      skipDuplicates: true,
    });
    const eventCount = await tx.alertEvent.count({ where: { alertId } });
    const current = await tx.alert.findUniqueOrThrow({ where: { id: alertId } });
    const alert = await tx.alert.update({
      where: { id: alertId },
      data: {
        eventCount,
        lastEventAt: newest > current.lastEventAt ? newest : current.lastEventAt,
        firstEventAt: oldest < current.firstEventAt ? oldest : current.firstEventAt,
      },
    });
    return { alert, created };
  });
}

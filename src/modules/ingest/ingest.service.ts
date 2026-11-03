import type { Prisma, Severity } from '@prisma/client';
import { prisma } from '../../db/prisma.js';
import { EventTypes } from '../../lib/eventTypes.js';
import type { EventInput, IngestScanBody } from './ingest.schemas.js';

export async function ingestEvents(events: EventInput[], apiKeyId: string) {
  const now = new Date();
  const created = await prisma.event.createManyAndReturn({
    data: events.map((event) => ({
      apiKeyId,
      type: event.type,
      severity: event.severity,
      source: event.source,
      actor: event.actor,
      ip: event.ip,
      message: event.message,
      metadata: event.metadata as Prisma.InputJsonObject,
      occurredAt: event.occurredAt ?? now,
    })),
  });
  return created;
}

export async function ingestScan(body: IngestScanBody, apiKeyId: string) {
  // Count findings per severity once, here, so list screens never have to load every finding.
  const summary: Record<Severity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const finding of body.findings) summary[finding.severity] += 1;

  const host = new URL(body.target).host;

  // One transaction: a scan is either stored completely or not at all.
  return prisma.$transaction(async (tx) => {
    const scan = await tx.scan.create({
      data: {
        apiKeyId,
        target: body.target,
        scannerVersion: body.scannerVersion,
        startedAt: body.startedAt,
        finishedAt: body.finishedAt,
        summary,
        findings: {
          create: body.findings.map((finding) => ({
            ...finding,
            evidence: finding.evidence as Prisma.InputJsonObject,
          })),
        },
      },
    });

    // Every critical finding also becomes an event, so the alert rules engine (and the live
    // feed) treat scan results like any other security signal.
    const critical = body.findings.filter((finding) => finding.severity === 'CRITICAL');
    const events = await tx.event.createManyAndReturn({
      data: critical.map((finding) => ({
        apiKeyId,
        type: EventTypes.ScanFindingCritical,
        severity: 'CRITICAL' as const,
        source: host,
        message: finding.title,
        metadata: { checkId: finding.checkId, scanId: scan.id, target: body.target },
        occurredAt: body.finishedAt,
      })),
    });

    return { scan, summary, events };
  });
}

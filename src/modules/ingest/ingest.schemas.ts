import { ScanCategory, Severity } from '@prisma/client';
import { z } from 'zod';

const MAX_METADATA_BYTES = 8_192;
const FIVE_MINUTES_MS = 5 * 60_000;

const isoDate = z.iso.datetime({ offset: true }).transform((value) => new Date(value));

const metadata = z
  .record(z.string(), z.unknown())
  .refine((value) => JSON.stringify(value).length <= MAX_METADATA_BYTES, 'metadata is too large');

export const eventInput = z.strictObject({
  // dotted lowercase names, e.g. "auth.login_failed"
  type: z
    .string()
    .max(100)
    .regex(/^[a-z0-9_]+(\.[a-z0-9_]+)+$/, 'type must look like "auth.login_failed"'),
  severity: z.enum(Severity).default('INFO'),
  source: z.string().trim().min(1).max(100),
  actor: z.string().trim().min(1).max(254).optional(),
  ip: z.union([z.ipv4(), z.ipv6()]).optional(),
  message: z.string().trim().min(1).max(1000),
  metadata: metadata.default({}),
  // Allow a little clock skew but refuse timestamps far in the future.
  occurredAt: isoDate
    .refine((date) => date.getTime() <= Date.now() + FIVE_MINUTES_MS, 'occurredAt is in the future')
    .optional(),
});

export const ingestEventsBody = z.strictObject({
  events: z.array(eventInput).min(1).max(500),
});

const findingInput = z.strictObject({
  checkId: z
    .string()
    .max(100)
    .regex(/^[A-Za-z0-9_.:-]+$/),
  category: z.enum(ScanCategory),
  severity: z.enum(Severity),
  title: z.string().trim().min(1).max(300),
  description: z.string().max(5000),
  evidence: metadata.default({}),
  remediation: z.string().max(5000),
  references: z
    .array(z.url({ protocol: /^https?$/ }).max(2048))
    .max(10)
    .default([]),
});

export const ingestScanBody = z
  .strictObject({
    target: z.url({ protocol: /^https?$/ }).max(2048),
    scannerVersion: z.string().trim().min(1).max(50),
    startedAt: isoDate,
    finishedAt: isoDate,
    findings: z.array(findingInput).max(1000),
  })
  .refine((scan) => scan.finishedAt >= scan.startedAt, {
    message: 'finishedAt must not be before startedAt',
    path: ['finishedAt'],
  });

export type EventInput = z.infer<typeof eventInput>;
export type IngestScanBody = z.infer<typeof ingestScanBody>;

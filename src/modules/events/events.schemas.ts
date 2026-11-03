import { Severity } from '@prisma/client';
import { z } from 'zod';
import { paginationQuery } from '../../lib/pagination.js';

const isoDate = z.iso.datetime({ offset: true }).transform((value) => new Date(value));

// "?severity=HIGH,CRITICAL" -> ['HIGH', 'CRITICAL']
const severityList = z
  .string()
  .transform((value) => value.split(',').map((part) => part.trim().toUpperCase()))
  .pipe(z.array(z.enum(Severity)).min(1).max(5));

export const listEventsQuery = paginationQuery.extend({
  type: z.string().max(100).optional(),
  severity: severityList.optional(),
  source: z.string().max(100).optional(),
  actor: z.string().max(254).optional(),
  ip: z.union([z.ipv4(), z.ipv6()]).optional(),
  q: z.string().trim().min(1).max(200).optional(), // free-text search in the message
  from: isoDate.optional(),
  to: isoDate.optional(),
  sort: z.enum(['occurredAt:desc', 'occurredAt:asc']).default('occurredAt:desc'),
});

const MAX_RANGE_MS = 90 * 86_400_000;

export const statsQuery = z
  .object({
    from: isoDate.optional(),
    to: isoDate.optional(),
    bucket: z.enum(['hour', 'day']).default('hour'),
  })
  .transform((query) => {
    const to = query.to ?? new Date();
    const from = query.from ?? new Date(to.getTime() - 24 * 3_600_000);
    return { from, to, bucket: query.bucket };
  })
  .refine((query) => query.from < query.to, 'from must be before to')
  .refine(
    (query) => query.to.getTime() - query.from.getTime() <= MAX_RANGE_MS,
    'Range is limited to 90 days',
  );

export const idParams = z.object({ id: z.uuid() });

export type ListEventsQuery = z.infer<typeof listEventsQuery>;
export type StatsQuery = z.infer<typeof statsQuery>;

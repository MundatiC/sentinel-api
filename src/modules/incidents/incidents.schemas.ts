import { IncidentStatus, Severity } from '@prisma/client';
import { z } from 'zod';
import { paginationQuery } from '../../lib/pagination.js';

const splitList = (value: string) => value.split(',').map((part) => part.trim().toUpperCase());

export const listIncidentsQuery = paginationQuery.extend({
  status: z
    .string()
    .transform(splitList)
    .pipe(z.array(z.enum(IncidentStatus)).min(1).max(4))
    .optional(),
  severity: z
    .string()
    .transform(splitList)
    .pipe(z.array(z.enum(Severity)).min(1).max(5))
    .optional(),
});

export const createIncidentBody = z.strictObject({
  title: z.string().trim().min(1).max(200),
  severity: z.enum(Severity),
  summary: z.string().max(5000).default(''),
  alertIds: z.array(z.uuid()).max(50).default([]),
});

export const updateIncidentBody = z
  .strictObject({
    title: z.string().trim().min(1).max(200),
    severity: z.enum(Severity),
    summary: z.string().max(5000),
    status: z.enum(IncidentStatus),
  })
  .partial()
  .refine((value) => Object.keys(value).length > 0, 'Provide at least one field');

export const addNoteBody = z.strictObject({
  body: z.string().trim().min(1).max(5000),
  // Analysts often write the timeline after the fact, so a note can be back-dated (never future-dated).
  occurredAt: z.iso
    .datetime({ offset: true })
    .transform((value) => new Date(value))
    .refine((date) => date.getTime() <= Date.now() + 5 * 60_000, 'occurredAt is in the future')
    .optional(),
});

export const linkAlertBody = z.strictObject({ alertId: z.uuid() });
export const idParams = z.object({ id: z.uuid() });

export type ListIncidentsQuery = z.infer<typeof listIncidentsQuery>;
export type CreateIncidentBody = z.infer<typeof createIncidentBody>;
export type UpdateIncidentBody = z.infer<typeof updateIncidentBody>;

import { AlertStatus, Severity } from '@prisma/client';
import { z } from 'zod';
import { paginationQuery } from '../../lib/pagination.js';

// "?status=OPEN,ACKNOWLEDGED" -> ['OPEN', 'ACKNOWLEDGED']
const splitList = (value: string) => value.split(',').map((part) => part.trim().toUpperCase());
const statusList = z
  .string()
  .transform(splitList)
  .pipe(z.array(z.enum(AlertStatus)).min(1).max(3));
const severityList = z
  .string()
  .transform(splitList)
  .pipe(z.array(z.enum(Severity)).min(1).max(5));

export const listAlertsQuery = paginationQuery.extend({
  status: statusList.optional(),
  severity: severityList.optional(),
  ruleId: z.uuid().optional(),
});

export const updateAlertBody = z
  .strictObject({
    status: z.enum(['ACKNOWLEDGED', 'RESOLVED']).optional(),
    assigneeId: z.uuid().nullable().optional(),
  })
  .refine((value) => value.status !== undefined || value.assigneeId !== undefined, {
    message: 'Provide status and/or assigneeId',
  });

export const idParams = z.object({ id: z.uuid() });

export type ListAlertsQuery = z.infer<typeof listAlertsQuery>;
export type UpdateAlertBody = z.infer<typeof updateAlertBody>;

import type { GroupBy, Severity } from '@prisma/client';
import { EventTypes } from '../../lib/eventTypes.js';

// Rules installed by `npm run db:seed`.
export const defaultRules: {
  name: string;
  description: string;
  eventType: string;
  groupBy: GroupBy;
  threshold: number;
  windowSeconds: number;
  severity: Severity;
  cooldownSeconds: number;
}[] = [
  {
    name: 'Brute-force login attempts',
    description: '5 failed logins from the same IP within 1 minute',
    eventType: EventTypes.LoginFailed,
    groupBy: 'IP',
    threshold: 5,
    windowSeconds: 60,
    severity: 'HIGH',
    cooldownSeconds: 300,
  },
  {
    name: 'Injection attempts',
    description: '3 injection-pattern requests from the same IP within 5 minutes',
    eventType: EventTypes.InjectionAttempt,
    groupBy: 'IP',
    threshold: 3,
    windowSeconds: 300,
    severity: 'CRITICAL',
    cooldownSeconds: 600,
  },
  {
    name: 'Critical scan finding',
    description: 'A scan reported a critical finding',
    eventType: EventTypes.ScanFindingCritical,
    groupBy: 'SOURCE',
    threshold: 1,
    windowSeconds: 60,
    severity: 'CRITICAL',
    cooldownSeconds: 0,
  },
];

import type { Event, Prisma } from '@prisma/client';
import { prisma } from '../../db/prisma.js';
import type { Logger } from '../../lib/logger.js';
import { evaluateEvents } from './engine.js';

export interface InternalEvent {
  type: string;
  severity: Event['severity'];
  source: string;
  actor?: string;
  ip?: string | null;
  message: string;
  metadata?: Prisma.InputJsonObject;
}

// The glue between "events were stored" and "rules are evaluated".
//
// Rule evaluation is deliberately NON-FATAL: by the time we run it the events are already saved,
// so if it fails we log the error and carry on. Otherwise the caller would see a 500 and retry,
// storing every event twice.
export function createEventPipeline(logger: Logger) {
  async function process(events: Event[]) {
    try {
      await evaluateEvents(events);
    } catch (err) {
      logger.error({ err }, 'Alert rule evaluation failed');
    }
  }

  // Lets the API watch itself: failed logins become events like any other, so the same
  // brute-force rule that protects your apps also protects Sentinel.
  async function record(input: InternalEvent) {
    try {
      const event = await prisma.event.create({
        data: {
          ...input,
          ip: input.ip ?? undefined,
          metadata: input.metadata ?? {},
          occurredAt: new Date(),
        },
      });
      await process([event]);
    } catch (err) {
      logger.error({ err }, 'Failed to record internal event');
    }
  }

  return { process, record };
}

export type EventPipeline = ReturnType<typeof createEventPipeline>;

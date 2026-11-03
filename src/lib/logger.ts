import { pino } from 'pino';
import type { Env } from '../config/env.js';

export function createLogger(env: Pick<Env, 'NODE_ENV' | 'LOG_LEVEL'>) {
  return pino({
    level: env.NODE_ENV === 'test' ? 'silent' : env.LOG_LEVEL,
    // Secrets must never reach the logs, even by accident.
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers["x-api-key"]',
        'res.headers["set-cookie"]',
        '*.password',
        '*.passwordHash',
        '*.refreshToken',
      ],
      censor: '[REDACTED]',
    },
    // Human-readable logs in development, JSON (machine-parsable) everywhere else.
    transport:
      env.NODE_ENV === 'development'
        ? { target: 'pino-pretty', options: { colorize: true } }
        : undefined,
  });
}

export type Logger = ReturnType<typeof createLogger>;

import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../lib/errors.js';
import type { Logger } from '../lib/logger.js';

// Every error leaves the API in this one shape:
// { error: { code, message, details?, requestId } }
function send(
  res: Parameters<ErrorRequestHandler>[2],
  status: number,
  code: string,
  message: string,
  details?: unknown,
) {
  res.status(status).json({
    error: {
      code,
      message,
      ...(details === undefined ? {} : { details }),
      requestId: res.locals.requestId,
    },
  });
}

export const notFoundHandler: RequestHandler = (_req, res) => {
  send(res, 404, 'NOT_FOUND', 'Route not found');
};

export function createErrorHandler(logger: Logger): ErrorRequestHandler {
  // Express recognises error handlers by their 4 parameters, so `_next` must stay.
  return (err, _req, res, _next) => {
    if (err instanceof AppError) {
      return send(res, err.status, err.code, err.message, err.details);
    }
    if (err instanceof ZodError) {
      return send(res, 400, 'VALIDATION_ERROR', 'Invalid request', err.issues);
    }
    // Errors thrown by express.json(): malformed JSON or body too large.
    if (err?.type === 'entity.parse.failed') {
      return send(res, 400, 'BAD_REQUEST', 'Malformed JSON body');
    }
    if (err?.type === 'entity.too.large') {
      return send(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body is too large');
    }
    // Anything else is a bug. Log the details for us, but tell the client nothing about
    // internals (no stack traces, no SQL, no file paths).
    logger.error({ err, requestId: res.locals.requestId }, 'Unhandled error');
    return send(res, 500, 'INTERNAL_ERROR', 'Something went wrong');
  };
}

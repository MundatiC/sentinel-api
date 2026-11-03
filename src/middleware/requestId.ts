import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

// Accept a caller-supplied id only if it looks safe. Otherwise a client could put newlines
// or huge strings in the header and pollute our logs ("log injection").
const SAFE_ID = /^[A-Za-z0-9._-]{8,64}$/;

export const requestId: RequestHandler = (req, res, next) => {
  const incoming = req.header('x-request-id');
  const id = incoming && SAFE_ID.test(incoming) ? incoming : randomUUID();
  res.locals.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
};

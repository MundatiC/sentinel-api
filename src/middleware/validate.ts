import type { RequestHandler } from 'express';
import type { ZodType } from 'zod';

// Validates body / query / params with zod. A failure throws a ZodError, which the central
// error handler turns into a 400 VALIDATION_ERROR response.
//
// Parsed values replace the raw ones, so handlers only ever see data that passed validation:
//   body   -> req.body
//   query  -> res.locals.query   (req.query is read-only in Express 5)
//   params -> res.locals.params
export function validate(schemas: {
  body?: ZodType;
  query?: ZodType;
  params?: ZodType;
}): RequestHandler {
  return (req, res, next) => {
    if (schemas.body) req.body = schemas.body.parse(req.body ?? {});
    if (schemas.query) res.locals.query = schemas.query.parse(req.query);
    if (schemas.params) res.locals.params = schemas.params.parse(req.params);
    next();
  };
}

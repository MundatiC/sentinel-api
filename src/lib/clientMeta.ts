import type { Request } from 'express';

// Who is calling? Used for audit logs and refresh-token records.
// `req.ip` honours the TRUST_PROXY setting, so it is only as trustworthy as that config.
export function clientMeta(req: Request) {
  return {
    ip: req.ip ?? null,
    userAgent: req.get('user-agent')?.slice(0, 255) ?? null,
  };
}

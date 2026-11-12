import { timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import type { RequestHandler } from 'express';

// When the dashboard proxies API calls (Vercel rewrite), the number of hops between the visitor and this
// process differs from a direct call, and Express's numeric `trust proxy` cannot be right for both: the
// value that credits proxied visitors lets a direct caller forge X-Forwarded-For.
//
// So the proxy vouches for the visitor instead: it sends the IP it saw in `X-Sentinel-Client-IP` together with
// a shared secret. Only a request carrying the right secret may set req.ip this way; everyone else keeps
// the IP Express derived from the (fixed-length) platform chain.
export const PROXY_SECRET_HEADER = 'x-sentinel-proxy-secret';
export const CLIENT_IP_HEADER = 'x-sentinel-client-ip';

export function verifiedProxyIp(secret: string | undefined): RequestHandler {
  if (!secret) return (_req, _res, next) => next();
  const expected = Buffer.from(secret);
  return (req, _res, next) => {
    const given = Buffer.from(req.get(PROXY_SECRET_HEADER) ?? '');
    const ip = req.get(CLIENT_IP_HEADER)?.trim();
    if (given.length === expected.length && timingSafeEqual(given, expected) && ip && isIP(ip)) {
      // An own property shadows Express's req.ip getter; everything downstream (rate limits, audit log) reads it.
      Object.defineProperty(req, 'ip', { value: ip, configurable: true });
    }
    next();
  };
}

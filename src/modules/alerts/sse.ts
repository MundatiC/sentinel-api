import type { Request, RequestHandler, Response } from 'express';
import { prisma } from '../../db/prisma.js';
import { AppError } from '../../lib/errors.js';
import { alertBus } from './alertBus.js';

const HEARTBEAT_MS = 25_000;
const MAX_STREAMS_PER_USER = 5;
const MAX_STREAMS_TOTAL = 200;

const openStreams = new Map<string, number>(); // userId -> number of open streams
let totalStreams = 0;

// Server-Sent Events: one long-lived HTTP response that we keep writing to.
// The browser (or `fetch`) reads it as a stream of "event: ...\ndata: ...\n\n" blocks.
//
// Safeguards, because an open connection is a resource an attacker could try to exhaust:
//   - capped per user and in total
//   - closed when the access token expires (the client reconnects with a fresh token)
//   - heartbeat re-checks the user is still active, and keeps proxies from timing out
export function alertStream(heartbeatMs = HEARTBEAT_MS): RequestHandler {
  return (req: Request, res: Response) => {
    const user = req.user!;
    if (
      totalStreams >= MAX_STREAMS_TOTAL ||
      (openStreams.get(user.id) ?? 0) >= MAX_STREAMS_PER_USER
    ) {
      throw new AppError(429, 'TOO_MANY_STREAMS', 'Too many open live connections');
    }
    openStreams.set(user.id, (openStreams.get(user.id) ?? 0) + 1);
    totalStreams += 1;

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no', // tell nginx not to buffer the stream
    });
    res.write('retry: 5000\n\n'); // browser reconnect delay
    res.write(': connected\n\n');

    const unsubscribe = alertBus.subscribe((message) => {
      // JSON.stringify escapes newlines, so attacker-controlled text cannot break the SSE framing.
      res.write(`event: ${message.type}\ndata: ${JSON.stringify(message.alert)}\n\n`);
    });

    let closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      clearInterval(heartbeat);
      clearTimeout(expiry);
      unsubscribe();
      const left = (openStreams.get(user.id) ?? 1) - 1;
      if (left <= 0) openStreams.delete(user.id);
      else openStreams.set(user.id, left);
      totalStreams -= 1;
      res.end();
    };

    const heartbeat = setInterval(async () => {
      try {
        const current = await prisma.user.findUnique({
          where: { id: user.id },
          select: { isActive: true },
        });
        if (!current?.isActive) return cleanup();
        res.write(': keep-alive\n\n');
      } catch {
        cleanup();
      }
    }, heartbeatMs);

    const msUntilTokenExpires = Math.max(0, Number(res.locals.tokenExpiresAt) - Date.now());
    const expiry = setTimeout(cleanup, msUntilTokenExpires);

    req.on('close', cleanup);
  };
}

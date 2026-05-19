import { NextRequest, NextResponse } from 'next/server';
import { log } from '@/lib/logger';

type RouteHandler = (req: NextRequest, ctx: unknown) => Promise<NextResponse>;

/**
 * Wraps a route handler with Winston request logging.
 * Logs method, path, status code, and duration on every response.
 */
export function withLogging(handler: RouteHandler): RouteHandler {
  return async (req: NextRequest, ctx: unknown) => {
    const start = Date.now();
    const { method, nextUrl } = req;

    try {
      const res = await handler(req, ctx);
      log.info(`${method} ${nextUrl.pathname} ${res.status} — ${Date.now() - start}ms`);
      return res;
    } catch (error) {
      log.error(`${method} ${nextUrl.pathname} 500 — ${Date.now() - start}ms`, error as Error);
      return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
    }
  };
}

import { NextRequest, NextResponse } from 'next/server';
import { log } from '@/lib/logger';

type RouteHandler<Ctx> = (req: NextRequest, ctx: Ctx) => Promise<NextResponse>;

/**
 * Wraps a route handler with Winston request logging.
 * Logs method, path, status code, and duration on every response.
 * Cualquier excepción no prevista queda registrada y se responde un 500 genérico
 * (sin detalles internos) en lugar de dejar que escape.
 */
export function withLogging<Ctx = unknown>(handler: RouteHandler<Ctx>): RouteHandler<Ctx> {
  return async (req: NextRequest, ctx: Ctx) => {
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

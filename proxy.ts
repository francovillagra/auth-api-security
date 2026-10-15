import { NextRequest, NextResponse } from 'next/server';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const PROTECTED_PREFIXES = ['/api/users'];
const RATE_LIMITED_PREFIXES = ['/api/auth'];

const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 10_000;

// ── Rate limiter ──────────────────────────────────────────────────────────────
// Upstash Redis in production; in-memory Map fallback for local dev (o si Redis falla).

let upstashLimit: Ratelimit | null = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  upstashLimit = new Ratelimit({
    redis: Redis.fromEnv(),
    limiter: Ratelimit.slidingWindow(RATE_LIMIT, '10 s'),
    analytics: false,
  });
}

const MAX_TRACKED_KEYS = 10_000;
const inMemoryStore = new Map<string, { count: number; resetAt: number }>();

function inMemoryRateLimit(key: string, limit = RATE_LIMIT, windowMs = RATE_WINDOW_MS) {
  const now = Date.now();

  // Acota la memoria: descarta lo vencido cuando el mapa crece demasiado.
  if (inMemoryStore.size >= MAX_TRACKED_KEYS) {
    for (const [storedKey, record] of inMemoryStore) {
      if (record.resetAt <= now) inMemoryStore.delete(storedKey);
    }
  }

  const record = inMemoryStore.get(key);
  if (!record || record.resetAt <= now) {
    inMemoryStore.set(key, { count: 1, resetAt: now + windowMs });
    return { success: true, reset: now + windowMs };
  }
  if (record.count >= limit) return { success: false, reset: record.resetAt };
  record.count++;
  return { success: true, reset: record.resetAt };
}

async function checkRateLimit(identifier: string) {
  if (upstashLimit) {
    try {
      const result = await upstashLimit.limit(identifier);
      return { success: result.success, reset: result.reset };
    } catch (error) {
      // Si Redis no responde se sigue limitando en memoria en lugar de abrir la puerta.
      console.warn('[proxy] rate limiter de Upstash no disponible, uso memoria:', (error as Error).message);
    }
  }
  return inMemoryRateLimit(identifier);
}

/**
 * IP del cliente para el rate limiting.
 *
 * Supone el despliegue en Vercel, donde la plataforma fija `x-real-ip` y `x-forwarded-for`
 * con la IP real y descarta lo que mande el cliente. Si el servicio se publica detrás de otro
 * proxy, este dato hay que revisarlo (ver README). Si solo hay `x-forwarded-for` se usa el
 * ÚLTIMO valor, que es el que agregó el proxy de confianza; el primero lo puede inventar el cliente.
 */
function clientIp(req: NextRequest): string {
  const realIp = req.headers.get('x-real-ip')?.trim();
  if (realIp) return realIp;
  const hops = req.headers.get('x-forwarded-for')?.split(',').map((hop) => hop.trim()).filter(Boolean);
  return hops?.at(-1) ?? 'anonymous';
}

// ── CORS ──────────────────────────────────────────────────────────────────────
// Lista explícita de orígenes (CORS_ORIGIN, separados por coma). Sin configurar, no se
// agrega ningún header CORS y el navegador solo permite el mismo origen. No se admite "*".

function allowedOrigins(): string[] {
  return (process.env.CORS_ORIGIN ?? '')
    .split(',')
    .map((origin) => origin.trim().replace(/\/$/, ''))
    .filter((origin) => origin !== '' && origin !== '*');
}

function withCors(res: NextResponse, origin: string | null): NextResponse {
  res.headers.append('Vary', 'Origin');
  if (origin && allowedOrigins().includes(origin)) {
    res.headers.set('Access-Control-Allow-Origin', origin);
  }
  return res;
}

function preflight(origin: string | null): NextResponse {
  const res = new NextResponse(null, { status: 204 });
  if (origin && allowedOrigins().includes(origin)) {
    res.headers.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
    res.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.headers.set('Access-Control-Max-Age', '600');
  }
  return withCors(res, origin);
}

// ── Proxy handler ─────────────────────────────────────────────────────────────

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const { method } = req;
  const origin = req.headers.get('origin');

  // CORS preflight
  if (method === 'OPTIONS') return preflight(origin);

  // Request logging (Winston corre en los route handlers; acá alcanza con console)
  console.log(`[proxy] ${method} ${pathname}`);

  // Rate limiting for /api/auth/*
  const isRateLimited = RATE_LIMITED_PREFIXES.some((p) => pathname.startsWith(p));
  if (isRateLimited) {
    const ip = clientIp(req);
    const { success, reset } = await checkRateLimit(`auth:${ip}`);

    if (!success) {
      const retryAfter = reset ? Math.max(1, Math.ceil((reset - Date.now()) / 1000)) : 10;
      console.warn(`[proxy] 429 rate limited: ${ip} → ${pathname}`);
      return withCors(
        NextResponse.json(
          { error: 'Too many requests', retryAfter },
          {
            status: 429,
            headers: {
              'Retry-After': String(retryAfter),
              'X-RateLimit-Limit': String(RATE_LIMIT),
              'X-RateLimit-Remaining': '0',
              'X-RateLimit-Reset': String(reset ?? 0),
            },
          }
        ),
        origin
      );
    }
  }

  // Auth guard for /api/users/* (la verificación completa del token la hace el route handler)
  const isProtected = PROTECTED_PREFIXES.some((p) => pathname.startsWith(p));
  if (isProtected) {
    const authHeader = req.headers.get('authorization');
    if (!/^Bearer\s+\S+$/i.test(authHeader ?? '')) {
      return withCors(NextResponse.json({ error: 'Authorization header required' }, { status: 401 }), origin);
    }
  }

  return withCors(NextResponse.next(), origin);
}

export const config = {
  matcher: ['/api/:path*'],
};

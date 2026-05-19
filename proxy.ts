import { NextRequest, NextResponse } from 'next/server';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const PROTECTED_PREFIXES = ['/api/users'];
const RATE_LIMITED_PREFIXES = ['/api/auth'];

// ── Rate limiter ──────────────────────────────────────────────────────────────
// Upstash Redis in production; in-memory Map fallback for local dev.

let upstashLimit: Ratelimit | null = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  upstashLimit = new Ratelimit({
    redis: Redis.fromEnv(),
    limiter: Ratelimit.slidingWindow(5, '10 s'),
    analytics: false,
  });
}

const inMemoryStore = new Map<string, { count: number; resetAt: number }>();

function inMemoryRateLimit(key: string, limit = 5, windowMs = 10_000) {
  const now = Date.now();
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
    const result = await upstashLimit.limit(identifier);
    return { success: result.success, reset: result.reset };
  }
  return inMemoryRateLimit(identifier);
}

// ── Proxy handler ─────────────────────────────────────────────────────────────

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const { method } = req;
  const start = Date.now();

  // CORS preflight
  if (method === 'OPTIONS') {
    return new NextResponse(null, { status: 204 });
  }

  // Request logging (console is Edge-safe; Winston runs in Node.js route handlers)
  console.log(`[proxy] ${method} ${pathname}`);

  // Rate limiting for /api/auth/*
  const isRateLimited = RATE_LIMITED_PREFIXES.some((p) => pathname.startsWith(p));
  if (isRateLimited) {
    const ip =
      req.headers.get('x-forwarded-for')?.split(',')[0].trim() ??
      req.headers.get('x-real-ip') ??
      'anonymous';

    const { success, reset } = await checkRateLimit(`auth:${ip}`);

    if (!success) {
      const retryAfter = reset ? Math.ceil((reset - Date.now()) / 1000) : 10;
      console.warn(`[proxy] 429 rate limited: ${ip} → ${pathname}`);
      return NextResponse.json(
        { error: 'Too many requests', retryAfter },
        {
          status: 429,
          headers: {
            'Retry-After': String(retryAfter),
            'X-RateLimit-Limit': '5',
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(reset ?? 0),
          },
        }
      );
    }
  }

  // Auth guard for /api/users/*
  const isProtected = PROTECTED_PREFIXES.some((p) => pathname.startsWith(p));
  if (isProtected) {
    const authHeader = req.headers.get('authorization');
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json({ error: 'Authorization header required' }, { status: 401 });
    }
  }

  const res = NextResponse.next();
  res.headers.set('X-Response-Time', `${Date.now() - start}ms`);
  return res;
}

export const config = {
  matcher: ['/api/:path*'],
};

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';

function req(path: string, { method = 'POST', headers = {} }: { method?: string; headers?: Record<string, string> } = {}) {
  return new NextRequest(`http://localhost${path}`, { method, headers });
}

/** Importa proxy.ts desde cero: el contador en memoria y la configuración leída del entorno arrancan limpios. */
async function loadProxy() {
  vi.resetModules();
  return (await import('../proxy')).proxy;
}

beforeEach(() => {
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.doUnmock('@upstash/ratelimit');
});

describe('rate limiting de /api/auth/*', () => {
  it('permite 5 pedidos por IP cada 10 s y responde 429 con Retry-After desde el 6.º', async () => {
    const proxy = await loadProxy();
    const statuses: number[] = [];
    let last: Response | undefined;
    for (let i = 0; i < 7; i++) {
      last = await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.9' } }));
      statuses.push(last.status);
    }
    expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
    expect(Number(last!.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(last!.headers.get('x-ratelimit-limit')).toBe('5');
    expect(await last!.json()).toMatchObject({ error: 'Too many requests' });
  });

  it('cada IP tiene su propio contador', async () => {
    const proxy = await loadProxy();
    for (let i = 0; i < 5; i++) await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.1' } }));
    expect((await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.1' } }))).status).toBe(429);
    expect((await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.2' } }))).status).toBe(200);
  });

  it('inventar X-Forwarded-For no sirve cuando la plataforma fija x-real-ip', async () => {
    const proxy = await loadProxy();
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      statuses.push((await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.50', 'x-forwarded-for': `198.51.100.${i}` } }))).status);
    }
    expect(statuses.filter((s) => s === 429).length).toBe(35);
  });

  it('con solo X-Forwarded-For se usa el último valor (el del proxy de confianza), no el primero que escribe el cliente', async () => {
    const proxy = await loadProxy();
    const statuses: number[] = [];
    for (let i = 0; i < 40; i++) {
      statuses.push((await proxy(req('/api/auth/login', { headers: { 'x-forwarded-for': `198.51.100.${i}, 192.0.2.77` } }))).status);
    }
    expect(statuses.filter((s) => s === 429).length).toBe(35);
  });

  it('login, registro y refresh comparten el mismo contador por IP', async () => {
    const proxy = await loadProxy();
    const paths = ['/api/auth/register', '/api/auth/login', '/api/auth/refresh', '/api/auth/login', '/api/auth/refresh', '/api/auth/login'];
    const statuses: number[] = [];
    for (const path of paths) statuses.push((await proxy(req(path, { headers: { 'x-real-ip': '192.0.2.5' } }))).status);
    expect(statuses[5]).toBe(429);
  });

  it('no limita rutas fuera de /api/auth', async () => {
    const proxy = await loadProxy();
    const headers = { 'x-real-ip': '192.0.2.9', authorization: 'Bearer abc' };
    for (let i = 0; i < 20; i++) {
      expect((await proxy(req('/api/users/me', { method: 'GET', headers }))).status).toBe(200);
    }
  });

  it('si Upstash falla, sigue limitando en memoria en lugar de dejar pasar todo o romper', async () => {
    vi.stubEnv('UPSTASH_REDIS_REST_URL', 'https://redis.example.test');
    vi.stubEnv('UPSTASH_REDIS_REST_TOKEN', 'token-de-prueba');
    vi.resetModules();
    vi.doMock('@upstash/ratelimit', () => {
      class Ratelimit {
        static slidingWindow() {
          return {};
        }
        limit() {
          return Promise.reject(new Error('redis caído'));
        }
      }
      return { Ratelimit };
    });
    vi.doMock('@upstash/redis', () => ({ Redis: { fromEnv: () => ({}) } }));
    const { proxy } = await import('../proxy');

    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await proxy(req('/api/auth/login', { headers: { 'x-real-ip': '203.0.113.77' } }))).status);
    expect(statuses).toEqual([200, 200, 200, 200, 200, 429, 429]);
    vi.doUnmock('@upstash/redis');
  });
});

describe('guardia de /api/users/*', () => {
  it('401 si no hay encabezado Authorization con Bearer', async () => {
    const proxy = await loadProxy();
    expect((await proxy(req('/api/users/me', { method: 'GET' }))).status).toBe(401);
    expect((await proxy(req('/api/users/me', { method: 'GET', headers: { authorization: 'Basic abc' } }))).status).toBe(401);
    expect((await proxy(req('/api/users/me', { method: 'GET', headers: { authorization: 'Bearer ' } }))).status).toBe(401);
  });

  it('deja pasar un Bearer (la validez del token la decide el route handler)', async () => {
    const proxy = await loadProxy();
    expect((await proxy(req('/api/users/me', { method: 'GET', headers: { authorization: 'bearer abc.def.ghi' } }))).status).toBe(200);
  });
});

describe('CORS', () => {
  const FRONT = 'https://frontend.example.test';

  it('sin CORS_ORIGIN no agrega ningún header Access-Control-*', async () => {
    vi.stubEnv('CORS_ORIGIN', '');
    const proxy = await loadProxy();
    const res = await proxy(req('/api/auth/login', { headers: { origin: FRONT, 'x-real-ip': '192.0.2.1' } }));
    expect([...res.headers.keys()].filter((h) => h.startsWith('access-control-'))).toEqual([]);
    expect(res.headers.get('vary')).toContain('Origin');
  });

  it('"*" no se admite como valor de CORS_ORIGIN', async () => {
    vi.stubEnv('CORS_ORIGIN', '*');
    const proxy = await loadProxy();
    const res = await proxy(req('/api/auth/login', { headers: { origin: FRONT, 'x-real-ip': '192.0.2.2' } }));
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('refleja solo los orígenes de la lista, uno por vez, y avisa con Vary: Origin', async () => {
    vi.stubEnv('CORS_ORIGIN', `${FRONT}/, https://admin.example.test`);
    const proxy = await loadProxy();

    const ok = await proxy(req('/api/auth/login', { headers: { origin: FRONT, 'x-real-ip': '192.0.2.3' } }));
    expect(ok.headers.get('access-control-allow-origin')).toBe(FRONT);
    expect(ok.headers.get('vary')).toContain('Origin');

    const second = await proxy(req('/api/auth/login', { headers: { origin: 'https://admin.example.test', 'x-real-ip': '192.0.2.4' } }));
    expect(second.headers.get('access-control-allow-origin')).toBe('https://admin.example.test');

    const evil = await proxy(req('/api/auth/login', { headers: { origin: 'https://evil.example.test', 'x-real-ip': '192.0.2.5' } }));
    expect(evil.headers.get('access-control-allow-origin')).toBeNull();

    const lookalike = await proxy(req('/api/auth/login', { headers: { origin: `${FRONT}.evil.test`, 'x-real-ip': '192.0.2.6' } }));
    expect(lookalike.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('el preflight de un origen permitido incluye PATCH y los headers necesarios', async () => {
    vi.stubEnv('CORS_ORIGIN', FRONT);
    const proxy = await loadProxy();
    const res = await proxy(req('/api/admin/users/abc/role', { method: 'OPTIONS', headers: { origin: FRONT, 'access-control-request-method': 'PATCH' } }));
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe(FRONT);
    expect(res.headers.get('access-control-allow-methods')).toContain('PATCH');
    expect(res.headers.get('access-control-allow-headers')).toBe('Content-Type, Authorization');
  });

  it('el preflight de un origen no permitido no recibe ningún permiso', async () => {
    vi.stubEnv('CORS_ORIGIN', FRONT);
    const proxy = await loadProxy();
    const res = await proxy(req('/api/auth/login', { method: 'OPTIONS', headers: { origin: 'https://evil.example.test', 'access-control-request-method': 'POST' } }));
    expect(res.status).toBe(204);
    expect([...res.headers.keys()].filter((h) => h.startsWith('access-control-'))).toEqual([]);
  });

  it('las respuestas 429 también llevan CORS para que el frontend pueda leerlas', async () => {
    vi.stubEnv('CORS_ORIGIN', FRONT);
    const proxy = await loadProxy();
    let res: Response | undefined;
    for (let i = 0; i < 6; i++) res = await proxy(req('/api/auth/login', { headers: { origin: FRONT, 'x-real-ip': '192.0.2.10' } }));
    expect(res!.status).toBe(429);
    expect(res!.headers.get('access-control-allow-origin')).toBe(FRONT);
  });
});

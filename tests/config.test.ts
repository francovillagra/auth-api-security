import { describe, expect, it } from 'vitest';
import config from '../next.config';

async function headersFor(source: string) {
  const rules = await config.headers!();
  const rule = rules.find((r) => r.source === source);
  return Object.fromEntries((rule?.headers ?? []).map((h) => [h.key, h.value]));
}

describe('next.config.ts', () => {
  it('no agrega CORS por configuración estática (se resuelve en proxy.ts con lista de orígenes)', async () => {
    const rules = await config.headers!();
    const keys = rules.flatMap((r) => r.headers.map((h) => h.key.toLowerCase()));
    expect(keys.some((k) => k.startsWith('access-control-'))).toBe(false);
  });

  it('las rutas /api no se cachean y tienen una CSP que no carga nada', async () => {
    const api = await headersFor('/api/(.*)');
    expect(api['Cache-Control']).toBe('no-store');
    expect(api['Content-Security-Policy']).toContain("default-src 'none'");
    expect(api['Content-Security-Policy']).not.toContain('unsafe-inline');
  });

  it('la regla de /api va después de la general para que su CSP prevalezca', async () => {
    const rules = await config.headers!();
    const sources = rules.map((r) => r.source);
    expect(sources.indexOf('/api/(.*)')).toBeGreaterThan(sources.indexOf('/(.*)'));
  });

  it('mantiene los headers de seguridad generales', async () => {
    const all = await headersFor('/(.*)');
    expect(all['Strict-Transport-Security']).toContain('max-age=63072000');
    expect(all['X-Content-Type-Options']).toBe('nosniff');
    expect(all['X-Frame-Options']).toBe('DENY');
    expect(all['Content-Security-Policy']).toContain("frame-ancestors 'none'");
  });

  it('no anuncia el framework con X-Powered-By', () => {
    expect(config.poweredByHeader).toBe(false);
  });
});

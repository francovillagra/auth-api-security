import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadJwtSecrets, validateSecret } from '@/lib/secrets';

const STRONG_A = 'Qm9x7Lk2VdP4wT8nZc1RbYh6SfJ3uAe5GoXiNvKt0DyM';
const STRONG_B = 'f3Gz9WqLp2XnC7vBk1RtYh8JdSa5UeMoAi4NxKw6TyHc';

describe('validateSecret', () => {
  it('acepta un secreto aleatorio de 32+ caracteres', () => {
    expect(validateSecret('JWT_SECRET', STRONG_A)).toBe(STRONG_A);
  });

  it.each([undefined, '', '   '])('rechaza un secreto vacío o ausente (%j)', (value) => {
    expect(() => validateSecret('JWT_SECRET', value)).toThrow(/JWT_SECRET no está definido/);
  });

  it('rechaza secretos de menos de 32 caracteres', () => {
    expect(() => validateSecret('JWT_SECRET', 'Qm9x7Lk2VdP4wT8nZc1RbYh6SfJ3uAe')).toThrow(/demasiado corto/);
  });

  it.each([
    'change-this-in-production-0123456789abcdef',
    'change-this-in-production-too-0123456789abcdef',
    'reemplazar-con-secreto-seguro-openssl-rand-base64-32',
    'tu-your-secret-va-aca-0123456789abcdefghij',
    'este-es-un-example-0123456789abcdefghijklmno',
    'replace-me-with-a-real-secret-0123456789ab',
  ])('rechaza valores de ejemplo (%s)', (value) => {
    expect(() => validateSecret('JWT_SECRET', value)).toThrow(/valor de ejemplo/);
  });

  it('rechaza secretos con muy poca variedad de caracteres', () => {
    expect(() => validateSecret('JWT_SECRET', 'a'.repeat(64))).toThrow(/poca variedad/);
    expect(() => validateSecret('JWT_SECRET', 'ab12'.repeat(16))).toThrow(/poca variedad/);
  });

  it('nunca incluye el valor del secreto en el mensaje de error', () => {
    const secret = 'change-this-in-production-0123456789abcdef';
    try {
      validateSecret('JWT_SECRET', secret);
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).not.toContain(secret);
    }
  });
});

describe('loadJwtSecrets', () => {
  it('devuelve ambos secretos si son válidos y distintos', () => {
    expect(loadJwtSecrets({ JWT_SECRET: STRONG_A, JWT_REFRESH_SECRET: STRONG_B })).toEqual({ access: STRONG_A, refresh: STRONG_B });
  });

  it('rechaza secretos iguales entre sí (un refresh token serviría como access token)', () => {
    expect(() => loadJwtSecrets({ JWT_SECRET: STRONG_A, JWT_REFRESH_SECRET: STRONG_A })).toThrow(/distintos/);
  });

  it('falla si falta alguno de los dos', () => {
    expect(() => loadJwtSecrets({ JWT_SECRET: STRONG_A })).toThrow(/JWT_REFRESH_SECRET/);
    expect(() => loadJwtSecrets({ JWT_REFRESH_SECRET: STRONG_B })).toThrow(/JWT_SECRET/);
  });

  it.each(['.env.example', '.env.production.example'])('los valores de %s no se aceptan como secretos', (file) => {
    const env: Record<string, string> = {};
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const match = line.match(/^(JWT_SECRET|JWT_REFRESH_SECRET)="?([^"#]*)"?/);
      if (match) env[match[1]] = match[2];
    }
    expect(() => loadJwtSecrets(env)).toThrow();
  });
});

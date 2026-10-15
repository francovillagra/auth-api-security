import jwt from 'jsonwebtoken';
import { describe, expect, it } from 'vitest';
import {
  extractTokenFromHeader,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
} from '@/lib/auth';

const ACCESS_SECRET = process.env.JWT_SECRET!;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET!;
const payload = { userId: 'user-1', email: 'ana@example.com', role: 'USER' as const };

function decodeHeader(token: string) {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
}

describe('access tokens', () => {
  it('ida y vuelta: devuelve usuario, email y rol', () => {
    expect(verifyAccessToken(generateAccessToken(payload))).toEqual(payload);
  });

  it('se firman con HS256 y llevan emisor, audiencia y subject', () => {
    const token = generateAccessToken(payload);
    expect(decodeHeader(token).alg).toBe('HS256');
    const claims = jwt.decode(token) as jwt.JwtPayload;
    expect(claims.iss).toBe('auth-api-security');
    expect(claims.aud).toBe('auth-api-security:access');
    expect(claims.sub).toBe('user-1');
    expect((claims.exp as number) - (claims.iat as number)).toBe(15 * 60);
  });

  it('rechaza un token HS512 aunque esté firmado con el secreto correcto (algoritmo fijado)', () => {
    const token = jwt.sign(payload, ACCESS_SECRET, {
      algorithm: 'HS512',
      expiresIn: '5m',
      issuer: 'auth-api-security',
      audience: 'auth-api-security:access',
    });
    expect(verifyAccessToken(token)).toBeNull();
  });

  it('rechaza alg=none', () => {
    const token = jwt.sign({ ...payload, role: 'ADMIN' }, '', { algorithm: 'none' as 'HS256' });
    expect(verifyAccessToken(token)).toBeNull();
  });

  it('rechaza un token firmado con otro secreto', () => {
    const forged = jwt.sign(payload, 'change-this-in-production', {
      expiresIn: '5m',
      issuer: 'auth-api-security',
      audience: 'auth-api-security:access',
    });
    expect(verifyAccessToken(forged)).toBeNull();
  });

  it('rechaza tokens sin emisor/audiencia (como los que emitía la versión anterior)', () => {
    expect(verifyAccessToken(jwt.sign(payload, ACCESS_SECRET, { expiresIn: '5m' }))).toBeNull();
  });

  it('rechaza un token con la audiencia de refresh aunque lleve la firma del access', () => {
    const token = jwt.sign(payload, ACCESS_SECRET, {
      expiresIn: '5m',
      issuer: 'auth-api-security',
      audience: 'auth-api-security:refresh',
    });
    expect(verifyAccessToken(token)).toBeNull();
  });

  it('rechaza un refresh token usado como access token', () => {
    expect(verifyAccessToken(generateRefreshToken(payload))).toBeNull();
  });

  it('rechaza tokens vencidos', () => {
    const expired = jwt.sign(payload, ACCESS_SECRET, {
      expiresIn: -10,
      issuer: 'auth-api-security',
      audience: 'auth-api-security:access',
    });
    expect(verifyAccessToken(expired)).toBeNull();
  });

  it.each([
    ['sin userId', { email: 'a@b.co', role: 'USER' }],
    ['sin email', { userId: 'x', role: 'USER' }],
    ['con un rol inventado', { userId: 'x', email: 'a@b.co', role: 'SUPERADMIN' }],
    ['con el rol como número', { userId: 'x', email: 'a@b.co', role: 1 }],
  ])('rechaza un token firmado correctamente pero %s', (_label, claims) => {
    const token = jwt.sign(claims, ACCESS_SECRET, {
      expiresIn: '5m',
      issuer: 'auth-api-security',
      audience: 'auth-api-security:access',
    });
    expect(verifyAccessToken(token)).toBeNull();
  });

  it('rechaza basura', () => {
    expect(verifyAccessToken('')).toBeNull();
    expect(verifyAccessToken('no.es.un-jwt')).toBeNull();
  });
});

describe('refresh tokens', () => {
  it('ida y vuelta: devuelve usuario, rol, jti y vencimiento a 7 días', () => {
    const token = generateRefreshToken(payload, 'jti-fijo');
    const verified = verifyRefreshToken(token);
    expect(verified).toMatchObject({ ...payload, jti: 'jti-fijo' });
    const days = ((verified!.expiresAt.getTime() - Date.now()) / 86_400_000);
    expect(days).toBeGreaterThan(6.99);
    expect(days).toBeLessThanOrEqual(7);
  });

  it('dos tokens emitidos en el mismo segundo son distintos (jti único)', () => {
    const a = generateRefreshToken(payload);
    const b = generateRefreshToken(payload);
    expect(a).not.toBe(b);
    expect(verifyRefreshToken(a)!.jti).not.toBe(verifyRefreshToken(b)!.jti);
  });

  it('rechaza un access token usado como refresh token', () => {
    expect(verifyRefreshToken(generateAccessToken(payload))).toBeNull();
  });

  it('rechaza un token sin jti', () => {
    const token = jwt.sign(payload, REFRESH_SECRET, {
      expiresIn: '7d',
      issuer: 'auth-api-security',
      audience: 'auth-api-security:refresh',
    });
    expect(verifyRefreshToken(token)).toBeNull();
  });

  it('rechaza HS512 y alg=none', () => {
    const base = { expiresIn: '7d', issuer: 'auth-api-security', audience: 'auth-api-security:refresh', jwtid: 'x' } as const;
    expect(verifyRefreshToken(jwt.sign(payload, REFRESH_SECRET, { ...base, algorithm: 'HS512' }))).toBeNull();
    expect(verifyRefreshToken(jwt.sign(payload, '', { ...base, algorithm: 'none' as 'HS256' }))).toBeNull();
  });
});

describe('extractTokenFromHeader', () => {
  it.each([
    ['Bearer abc.def.ghi', 'abc.def.ghi'],
    ['bearer abc', 'abc'],
    ['BEARER   abc', 'abc'],
  ])('extrae el token de %j', (header, token) => {
    expect(extractTokenFromHeader(header)).toBe(token);
  });

  it.each([null, '', 'Bearer', 'Bearer ', 'Basic abc', 'Bearer a b', 'Token abc'])('devuelve null para %j', (header) => {
    expect(extractTokenFromHeader(header)).toBeNull();
  });
});

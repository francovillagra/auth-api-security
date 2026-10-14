import { NextRequest } from 'next/server';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { Role } from '@prisma/client';
import { loadJwtSecrets } from './secrets';

/** Falla al importarse si los secretos faltan, son débiles, de ejemplo o iguales entre sí. */
const SECRETS = loadJwtSecrets();

const ISSUER = 'auth-api-security';
/** Único algoritmo aceptado al verificar: evita confusión de algoritmos. */
const ALGORITHM = 'HS256' as const;
const BCRYPT_ROUNDS = 10;

export type TokenUse = 'access' | 'refresh';

/** Datos del usuario que viajan dentro de los tokens. */
export interface TokenPayload {
  userId: string;
  email: string;
  role: Role;
}

/** Refresh token verificado: además de los datos del usuario trae su identificador único. */
export interface RefreshTokenPayload extends TokenPayload {
  jti: string;
  expiresAt: Date;
}

const audience = (use: TokenUse) => `${ISSUER}:${use}`;

/** Returns the bcrypt hash of `password` using 10 salt rounds. */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Hash de una contraseña que nadie conoce, con el mismo costo que los reales. Se compara
 * cuando el email no existe para que la respuesta tarde lo mismo que con un email válido.
 */
const DUMMY_HASH = bcrypt.hashSync(randomUUID(), BCRYPT_ROUNDS);

/** Returns `true` if `password` matches the stored `hash`. */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Compara `password` siempre contra un hash: el del usuario si existe o uno falso si no,
 * de modo que el tiempo de respuesta no revele si el email está registrado.
 */
export async function verifyPasswordConstantTime(password: string, hash: string | undefined): Promise<boolean> {
  const matches = await bcrypt.compare(password, hash ?? DUMMY_HASH);
  return hash !== undefined && matches;
}

const accessClaims = (payload: TokenPayload) => ({ userId: payload.userId, email: payload.email, role: payload.role });

/** Issues a short-lived access token (15 minutes). */
export function generateAccessToken(payload: TokenPayload): string {
  return jwt.sign(accessClaims(payload), SECRETS.access, {
    algorithm: ALGORITHM,
    expiresIn: '15m',
    issuer: ISSUER,
    audience: audience('access'),
    subject: payload.userId,
  });
}

/**
 * Issues a long-lived refresh token (7 days). Lleva un `jti` único: dos tokens emitidos
 * en el mismo segundo nunca son idénticos y cada uno se puede identificar y revocar.
 */
export function generateRefreshToken(payload: TokenPayload, jti: string = randomUUID()): string {
  return jwt.sign(accessClaims(payload), SECRETS.refresh, {
    algorithm: ALGORITHM,
    expiresIn: '7d',
    issuer: ISSUER,
    audience: audience('refresh'),
    subject: payload.userId,
    jwtid: jti,
  });
}

function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (Object.values(Role) as string[]).includes(value);
}

function verify(token: string, secret: string, use: TokenUse): (jwt.JwtPayload & TokenPayload) | null {
  try {
    const decoded = jwt.verify(token, secret, { algorithms: [ALGORITHM], issuer: ISSUER, audience: audience(use) });
    if (typeof decoded === 'string') return null;
    const { userId, email, role } = decoded as Record<string, unknown>;
    if (typeof userId !== 'string' || typeof email !== 'string' || !isRole(role)) return null;
    return decoded as jwt.JwtPayload & TokenPayload;
  } catch {
    return null;
  }
}

/**
 * Verifies an access token and returns its payload.
 * Returns `null` if the token is invalid or expired.
 */
export function verifyAccessToken(token: string): TokenPayload | null {
  const decoded = verify(token, SECRETS.access, 'access');
  return decoded && { userId: decoded.userId, email: decoded.email, role: decoded.role };
}

/**
 * Verifies a refresh token and returns its payload.
 * Returns `null` if the token is invalid or expired.
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload | null {
  const decoded = verify(token, SECRETS.refresh, 'refresh');
  if (!decoded || typeof decoded.jti !== 'string' || typeof decoded.exp !== 'number') return null;
  return {
    userId: decoded.userId,
    email: decoded.email,
    role: decoded.role,
    jti: decoded.jti,
    expiresAt: new Date(decoded.exp * 1000),
  };
}

/**
 * Extracts the Bearer token from an `Authorization` header.
 * Returns `null` if the header is missing or malformed.
 */
export function extractTokenFromHeader(authHeader: string | null): string | null {
  const match = authHeader?.match(/^Bearer\s+(\S+)$/i);
  return match ? match[1] : null;
}

/**
 * Extracts and verifies the JWT from a request's Authorization header.
 * Returns the token payload, or `null` if the token is missing or invalid.
 */
export function getAuthUser(req: NextRequest): TokenPayload | null {
  const token = extractTokenFromHeader(req.headers.get('authorization'));
  if (!token) return null;
  return verifyAccessToken(token);
}

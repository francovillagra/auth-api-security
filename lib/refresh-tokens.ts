// lib/refresh-tokens.ts
//
// Sesiones con refresh tokens rotativos y revocables.
//
// Cada inicio de sesión (login o registro) abre una *sesión*: una "familia" de refresh tokens. Cada
// token se canjea UNA sola vez por uno nuevo de la misma familia:
//
//   login ──► T1 ──refresh──► T2 ──refresh──► T3 ...
//             (usado)         (usado)         (vigente)
//
// Si alguien presenta un token ya canjeado (T1 o T2), el cliente legítimo y quien lo copió tienen
// tokens de la misma cadena y no hay forma de saber cuál es cuál: se revoca la familia entera y el
// usuario tiene que volver a iniciar sesión. Es la detección de reutilización de la
// "refresh token rotation" (OAuth 2.0 Security BCP, RFC 9700).
//
// En la base se guarda solo el `jti` de cada token (no el token): sin el secreto de firma, una
// filtración de la tabla no sirve para fabricar sesiones.

import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { prisma } from '@/lib/db';
import { generateRefreshToken, verifyRefreshToken, type TokenPayload } from '@/lib/auth';
import { log } from '@/lib/logger';

const DAY_MS = 24 * 60 * 60 * 1000;

/** Vida de cada refresh token. */
export const REFRESH_TOKEN_TTL_MS = 7 * DAY_MS;
/** Tope absoluto de una sesión: por más que se renueve, a los 30 días hay que volver a iniciar sesión. */
export const SESSION_MAX_AGE_MS = 30 * DAY_MS;
/** Sesiones activas por usuario. Al abrir una más se cierra la que hace más tiempo no se renueva. */
export const MAX_ACTIVE_SESSIONS = 10;

type Db = Pick<Prisma.TransactionClient, 'refreshToken'>;

/** Redondea hacia abajo al segundo, como el claim `exp`, para que la base y el JWT digan lo mismo. */
const toSecond = (ms: number) => new Date(Math.floor(ms / 1000) * 1000);

/** Guarda el token y devuelve el JWT firmado. El vencimiento nunca pasa del tope de la sesión. */
async function insertToken(
  db: Db,
  user: TokenPayload,
  session: { familyId: string; sessionExpiresAt: Date },
  now: number,
): Promise<string> {
  const jti = randomUUID();
  const expiresAt = toSecond(Math.min(now + REFRESH_TOKEN_TTL_MS, session.sessionExpiresAt.getTime()));
  await db.refreshToken.create({
    data: { jti, familyId: session.familyId, userId: user.userId, expiresAt, sessionExpiresAt: session.sessionExpiresAt },
  });
  return generateRefreshToken(user, jti, expiresAt);
}

/** Revoca de una vez todos los tokens vigentes de una sesión. */
function revokeFamily(db: Db, familyId: string, now: number) {
  return db.refreshToken.updateMany({ where: { familyId, revokedAt: null }, data: { revokedAt: new Date(now) } });
}

/** Abre una sesión nueva y devuelve su primer refresh token. */
export async function startSession(user: TokenPayload): Promise<string> {
  const now = Date.now();
  const refreshToken = await insertToken(prisma, user, { familyId: randomUUID(), sessionExpiresAt: toSecond(now + SESSION_MAX_AGE_MS) }, now);

  try {
    // Mantenimiento oportunista: no hay tarea programada, así que cada inicio de sesión barre lo vencido.
    await prisma.refreshToken.deleteMany({ where: { expiresAt: { lt: new Date(now) } } });
    await enforceSessionLimit(user.userId, now);
  } catch (error) {
    // Un fallo acá no puede impedir que el usuario entre: el token ya está emitido.
    log.error(`Session maintenance failed for user ${user.userId}`, error as Error);
  }
  return refreshToken;
}

async function enforceSessionLimit(userId: string, now: number): Promise<void> {
  const active = await prisma.refreshToken.findMany({
    where: { userId, revokedAt: null, expiresAt: { gt: new Date(now) } },
    orderBy: { createdAt: 'asc' },
    select: { jti: true },
  });
  const surplus = active.length - MAX_ACTIVE_SESSIONS;
  if (surplus <= 0) return;

  // El token vigente de cada sesión es el último que se canjeó: ordenar por creación deja primero la
  // sesión que hace más tiempo no se usa.
  await prisma.refreshToken.updateMany({
    where: { jti: { in: active.slice(0, surplus).map((token) => token.jti) }, revokedAt: null },
    data: { revokedAt: new Date(now) },
  });
  log.info(`Session limit reached for user ${userId}: closed ${surplus} least recently used session(s)`);
}

export interface RotatedSession {
  /** Identidad actual del usuario (el rol sale de la base, no del token). */
  user: TokenPayload;
  refreshToken: string;
}

/**
 * Canjea un refresh token por uno nuevo de la misma sesión. Devuelve `null` si hay que responder 401:
 * firma inválida, token desconocido, vencido, ya usado (reutilización) o usuario inexistente.
 *
 * El canje es una transacción: "marcar el token como usado solo si sigue vigente" y "emitir el
 * siguiente" van juntos. Si dos pedidos llegan a la vez con el mismo token, el UPDATE condicional deja
 * pasar a uno solo; el otro lo ve ya usado, cierra la sesión y la transacción del primero ya está
 * confirmada, así que el token que acaba de emitir también queda revocado. Si algo falla antes de
 * emitir el nuevo, el canje se deshace y el cliente puede reintentar con el mismo token.
 */
export async function rotateRefreshToken(rawToken: string): Promise<RotatedSession | null> {
  const claims = verifyRefreshToken(rawToken);
  if (!claims) return null;
  const now = Date.now();

  const stored = await prisma.refreshToken.findUnique({ where: { jti: claims.jti } });
  if (!stored || stored.userId !== claims.userId) {
    // Un token con firma válida que la base no conoce: emitido antes de que existiera esta tabla,
    // o alguien con el secreto de firma. Merece quedar registrado.
    log.warn(`Refresh rejected: signed token not found in the database (user ${claims.userId})`);
    return null;
  }

  if (stored.revokedAt) {
    await revokeFamily(prisma, stored.familyId, now);
    log.warn(`Refresh token reuse detected: user ${stored.userId}, session ${stored.familyId} revoked`);
    return null;
  }
  if (stored.expiresAt.getTime() <= now) return null;

  const user = await prisma.user.findUnique({ where: { id: stored.userId } });
  if (!user) return null;
  const identity: TokenPayload = { userId: user.id, email: user.email, role: user.role };

  const refreshToken = await prisma.$transaction(async (tx) => {
    const consumed = await tx.refreshToken.updateMany({
      where: { jti: stored.jti, revokedAt: null },
      data: { revokedAt: new Date(now) },
    });
    if (consumed.count !== 1) {
      // Otro pedido lo canjeó entre la lectura y este UPDATE.
      await revokeFamily(tx, stored.familyId, now);
      return null;
    }
    return insertToken(tx, identity, stored, now);
  });

  if (!refreshToken) {
    log.warn(`Refresh token reuse detected (concurrent): user ${stored.userId}, session ${stored.familyId} revoked`);
    return null;
  }
  return { user: identity, refreshToken };
}

/**
 * Cierra la sesión a la que pertenece el refresh token, o todas las del usuario con `everywhere`.
 * No devuelve nada a propósito: el logout responde igual con un token válido, vencido o inventado.
 * Para `everywhere` el token tiene que seguir vigente, así un token viejo robado no sirve para
 * cerrarle todas las sesiones al dueño.
 */
export async function revokeSession(rawToken: string, { everywhere = false }: { everywhere?: boolean } = {}): Promise<void> {
  const claims = verifyRefreshToken(rawToken);
  if (!claims) return;

  const stored = await prisma.refreshToken.findUnique({ where: { jti: claims.jti } });
  if (!stored || stored.userId !== claims.userId) return;
  if (everywhere && stored.revokedAt) return;

  const now = new Date();
  const { count } = await prisma.refreshToken.updateMany({
    where: everywhere ? { userId: stored.userId, revokedAt: null } : { familyId: stored.familyId, revokedAt: null },
    data: { revokedAt: now },
  });
  log.info(
    everywhere
      ? `Logout everywhere: user ${stored.userId}, ${count} token(s) revoked`
      : `Logout: user ${stored.userId}, session ${stored.familyId}`,
  );
}

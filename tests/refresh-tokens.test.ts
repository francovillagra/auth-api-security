import jwt from 'jsonwebtoken';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { log } from '@/lib/logger';
import { generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { MAX_ACTIVE_SESSIONS, REFRESH_TOKEN_TTL_MS, SESSION_MAX_AGE_MS } from '@/lib/refresh-tokens';
import { POST as register } from '@/app/api/auth/register/route';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as refresh } from '@/app/api/auth/refresh/route';
import { POST as logout } from '@/app/api/auth/logout/route';
import { GET as me } from '@/app/api/users/me/route';
import { dbState } from './helpers/db-state';
import { bearer, jsonRequest, readJson } from './helpers/http';
import { PASSWORD, seedUser } from './helpers/seed';

const ctx = {};
const DAY = 86_400_000;

const signIn = (email: string) => login(jsonRequest('/api/auth/login', { body: { email, password: PASSWORD } }), ctx);
const refreshWith = (refreshToken: unknown) => refresh(jsonRequest('/api/auth/refresh', { body: { refreshToken } }), ctx);
const logoutWith = (body: unknown, headers?: Record<string, string>) => logout(jsonRequest('/api/auth/logout', { body, headers }), ctx);
const profile = (token: string) => me(jsonRequest('/api/users/me', { method: 'GET', headers: bearer(token) }), ctx);

const tokens = () => dbState.prisma.refreshTokens;
const jtiOf = (token: string) => (jwt.decode(token) as jwt.JwtPayload).jti as string;
const rowOf = (token: string) => tokens().find((t) => t.jti === jtiOf(token))!;
const isActive = (token: string) => rowOf(token).revokedAt === null;
const activeRows = () => tokens().filter((t) => t.revokedAt === null && t.expiresAt.getTime() > Date.now());
const allLogs = () => [log.info, log.warn, log.error, log.debug].flatMap((fn) => vi.mocked(fn).mock.calls.map((call) => String(call[0])));

interface Session {
  accessToken: string;
  refreshToken: string;
  user: { id: string; email: string };
}

/** Abre una sesión nueva (un login). Crea el usuario la primera vez. */
async function startSession(email = 'ana@example.com'): Promise<Session> {
  if (!dbState.prisma.users.some((u) => u.email === email)) await seedUser(email);
  return readJson(await signIn(email));
}

async function renew(token: string): Promise<{ accessToken: string; refreshToken: string }> {
  const res = await refreshWith(token);
  expect(res.status).toBe(200);
  return readJson(res);
}

afterEach(() => {
  vi.useRealTimers();
});

describe('al iniciar sesión se registra el refresh token', () => {
  it('login guarda el jti, el usuario y los vencimientos (7 días el token, 30 días la sesión)', async () => {
    const { refreshToken, user } = await startSession();

    expect(tokens()).toHaveLength(1);
    const row = rowOf(refreshToken);
    const claims = jwt.decode(refreshToken) as jwt.JwtPayload;
    expect(row).toMatchObject({ userId: user.id, revokedAt: null });
    expect(row.familyId).toMatch(/^[0-9a-f-]{36}$/);
    expect(row.expiresAt.getTime()).toBe(claims.exp! * 1000);
    expect(Math.abs(row.expiresAt.getTime() - Date.now() - REFRESH_TOKEN_TTL_MS)).toBeLessThan(5_000);
    expect(Math.abs(row.sessionExpiresAt.getTime() - Date.now() - SESSION_MAX_AGE_MS)).toBeLessThan(5_000);
  });

  it('register también abre una sesión', async () => {
    const res = await register(jsonRequest('/api/auth/register', { body: { email: 'nueva@example.com', password: PASSWORD } }), ctx);
    const body = await readJson(res);
    expect(res.status).toBe(201);
    expect(tokens()).toHaveLength(1);
    expect(rowOf(body.refreshToken).userId).toBe(body.user.id);
  });

  it('cada login es una sesión distinta, con su propia familia', async () => {
    const a = await startSession();
    const b = await startSession();
    expect(rowOf(a.refreshToken).familyId).not.toBe(rowOf(b.refreshToken).familyId);
    expect(activeRows()).toHaveLength(2);
  });

  it('en la base queda el identificador, no el token: nada que sirva para fabricar uno', async () => {
    const { refreshToken } = await startSession();
    expect(Object.keys(rowOf(refreshToken)).sort()).toEqual(['createdAt', 'expiresAt', 'familyId', 'jti', 'revokedAt', 'sessionExpiresAt', 'userId']);
    expect(JSON.stringify(tokens())).not.toContain(refreshToken);
  });
});

describe('POST /api/auth/refresh — rotación', () => {
  it('canjear un token lo revoca y entrega uno nuevo de la misma sesión', async () => {
    const first = await startSession();
    const next = await renew(first.refreshToken);

    expect(next.refreshToken).not.toBe(first.refreshToken);
    expect(isActive(first.refreshToken)).toBe(false);
    expect(isActive(next.refreshToken)).toBe(true);
    expect(rowOf(next.refreshToken).familyId).toBe(rowOf(first.refreshToken).familyId);
    expect(rowOf(next.refreshToken).sessionExpiresAt).toEqual(rowOf(first.refreshToken).sessionExpiresAt);
    expect((await profile(next.accessToken)).status).toBe(200);
  });

  it('la cadena de renovaciones sigue funcionando: cada token sirve una sola vez', async () => {
    let current = (await startSession()).refreshToken;
    for (let i = 0; i < 4; i++) current = (await renew(current)).refreshToken;
    expect(tokens()).toHaveLength(5);
    expect(activeRows()).toHaveLength(1);
  });
});

describe('POST /api/auth/refresh — detección de reutilización', () => {
  it('repetir un token ya canjeado da 401 y cierra la sesión entera, también el token legítimo más nuevo', async () => {
    const stolen = await startSession();
    const legit = await renew(stolen.refreshToken); // el cliente legítimo ya lo había canjeado

    expect((await refreshWith(stolen.refreshToken)).status).toBe(401); // alguien lo repite
    expect(tokens().every((t) => t.revokedAt !== null)).toBe(true);
    expect((await refreshWith(legit.refreshToken)).status).toBe(401); // y el que sigue quedó sin efecto
  });

  it('el atacante que canjea primero también queda afuera cuando el dueño intenta usar su copia', async () => {
    const original = await startSession();
    const attackers = await renew(original.refreshToken); // el atacante llegó primero

    expect((await refreshWith(original.refreshToken)).status).toBe(401); // el dueño lo intenta
    expect((await refreshWith(attackers.refreshToken)).status).toBe(401); // la sesión del atacante muere
  });

  it('queda registrado con ids, sin tokens ni emails', async () => {
    const { refreshToken, user } = await startSession();
    const renewed = await renew(refreshToken);
    await refreshWith(refreshToken);

    const warning = vi.mocked(log.warn).mock.calls.map((c) => String(c[0])).find((m) => /reuse/i.test(m));
    expect(warning).toBeDefined();
    expect(warning).toContain(user.id);
    expect(warning).toContain(rowOf(refreshToken).familyId);
    const logs = allLogs().join('\n');
    for (const secret of [refreshToken, renewed.refreshToken, renewed.accessToken, 'ana@example.com', PASSWORD]) {
      expect(logs).not.toContain(secret);
    }
  });

  it('la reutilización en una sesión no toca las otras sesiones del mismo usuario', async () => {
    const phone = await startSession();
    const laptop = await startSession();
    await renew(phone.refreshToken);
    await refreshWith(phone.refreshToken); // reutilización en el teléfono

    expect(isActive(laptop.refreshToken)).toBe(true);
    expect((await refreshWith(laptop.refreshToken)).status).toBe(200);
  });

  it('dos canjes simultáneos del mismo token: gana uno, el otro recibe 401 y la sesión se cierra', async () => {
    const { refreshToken } = await startSession();
    const [a, b] = await Promise.all([refreshWith(refreshToken), refreshWith(refreshToken)]);

    expect([a.status, b.status].sort()).toEqual([200, 401]);
    const winner = await readJson(a.status === 200 ? a : b);
    // Un uso doble del mismo token no se distingue de un robo: se cierra la sesión.
    expect((await refreshWith(winner.refreshToken)).status).toBe(401);
    expect(activeRows()).toHaveLength(0);
  });
});

describe('POST /api/auth/refresh — tokens que la base no reconoce o rechaza', () => {
  it('un token firmado por el servidor pero ausente de la base (por ejemplo emitido antes de esta versión) se rechaza', async () => {
    const user = await seedUser('ana@example.com');
    const orphan = generateRefreshToken({ userId: user.id, email: user.email, role: 'USER' });

    const res = await refreshWith(orphan);
    expect(res.status).toBe(401);
    expect(await readJson(res)).toEqual({ error: 'Invalid or expired refresh token' });
    expect(tokens()).toHaveLength(0);
  });

  it('un token desconocido no revoca las sesiones reales', async () => {
    const { refreshToken, user } = await startSession();
    const orphan = generateRefreshToken({ userId: user.id, email: user.email, role: 'USER' });
    expect((await refreshWith(orphan)).status).toBe(401);
    expect(isActive(refreshToken)).toBe(true);
  });

  it('un token vencido en la base se rechaza aunque el JWT todavía no haya vencido', async () => {
    const { refreshToken } = await startSession();
    rowOf(refreshToken).expiresAt = new Date(Date.now() - 1_000);
    expect((await refreshWith(refreshToken)).status).toBe(401);
  });

  it('si la fila pertenece a otro usuario que el token, se rechaza', async () => {
    const { refreshToken } = await startSession();
    const other = await seedUser('otra@example.com');
    rowOf(refreshToken).userId = other.id;
    expect((await refreshWith(refreshToken)).status).toBe(401);
  });

  it('el mismo error 401 para un token reutilizado, uno desconocido y basura', async () => {
    const { refreshToken, user } = await startSession();
    await renew(refreshToken);
    const reused = await refreshWith(refreshToken);
    const garbage = await refreshWith('basura');
    const orphan = await refreshWith(generateRefreshToken({ userId: user.id, email: 'ana@example.com', role: 'USER' }));

    for (const res of [reused, garbage, orphan]) {
      expect(res.status).toBe(401);
      expect(await readJson(res)).toEqual({ error: 'Invalid or expired refresh token' });
    }
  });

  it('si falla la emisión del token nuevo, el canje se deshace: el anterior sigue sirviendo y no se pierde la sesión', async () => {
    const { refreshToken } = await startSession();
    vi.spyOn(dbState.prisma.refreshToken, 'create').mockRejectedValueOnce(new Error('conexión caída'));

    const failed = await refreshWith(refreshToken);
    expect(failed.status).toBe(500);
    expect(await readJson(failed)).toEqual({ error: 'Internal server error' });
    expect(isActive(refreshToken)).toBe(true);
    expect((await refreshWith(refreshToken)).status).toBe(200);
  });
});

describe('vida de la sesión', () => {
  it('un refresh token no usado vence a los 7 días', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-01T12:00:00Z'));
    const { refreshToken } = await startSession();

    vi.setSystemTime(new Date('2026-10-08T11:59:00Z'));
    expect(isActive(refreshToken)).toBe(true);
    vi.setSystemTime(new Date('2026-10-08T12:00:01Z'));
    expect((await refreshWith(refreshToken)).status).toBe(401);
  });

  it('una sesión se puede renovar durante semanas, pero ningún token pasa de los 30 días desde el login', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const start = new Date('2026-10-01T12:00:00Z').getTime();
    vi.setSystemTime(start);
    let current = (await startSession()).refreshToken;

    for (const day of [6, 12, 18, 24]) {
      vi.setSystemTime(start + day * DAY);
      current = (await renew(current)).refreshToken;
    }

    // El token del día 24 habría vencido el día 31; la sesión lo recorta al día 30.
    const sessionEnd = start + 30 * DAY;
    expect(rowOf(current).expiresAt.getTime()).toBe(sessionEnd);
    expect((jwt.decode(current) as jwt.JwtPayload).exp).toBe(sessionEnd / 1000);

    vi.setSystemTime(sessionEnd - 1_000);
    expect(isActive(current)).toBe(true);
    vi.setSystemTime(sessionEnd + 1_000);
    expect((await refreshWith(current)).status).toBe(401);
  });
});

describe('POST /api/auth/logout', () => {
  it('cierra la sesión: el token ya no se puede canjear y toda la familia queda revocada', async () => {
    const first = await startSession();
    const second = await renew(first.refreshToken);

    const res = await logoutWith({ refreshToken: second.refreshToken });
    expect(res.status).toBe(204);
    expect(tokens().every((t) => t.revokedAt !== null)).toBe(true);
    expect((await refreshWith(second.refreshToken)).status).toBe(401);
  });

  it('no toca las otras sesiones del usuario', async () => {
    const phone = await startSession();
    const laptop = await startSession();
    await logoutWith({ refreshToken: phone.refreshToken });

    expect(isActive(phone.refreshToken)).toBe(false);
    expect((await refreshWith(laptop.refreshToken)).status).toBe(200);
  });

  it('es idempotente y no revela nada: repetido, con basura, con un token desconocido o con un access token responde 204 sin cambiar nada', async () => {
    const { refreshToken, accessToken, user } = await startSession();
    await logoutWith({ refreshToken });
    const snapshot = JSON.stringify(tokens());

    const unknown = generateRefreshToken({ userId: user.id, email: 'ana@example.com', role: 'USER' });
    for (const token of [refreshToken, 'basura', unknown, accessToken]) {
      expect((await logoutWith({ refreshToken: token })).status).toBe(204);
    }
    expect(JSON.stringify(tokens())).toBe(snapshot);
  });

  it('con everywhere: true cierra todas las sesiones del usuario y ninguna de otro usuario', async () => {
    const a1 = await startSession('ana@example.com');
    const a2 = await startSession('ana@example.com');
    const b1 = await startSession('beto@example.com');

    expect((await logoutWith({ refreshToken: a1.refreshToken, everywhere: true })).status).toBe(204);
    expect(isActive(a1.refreshToken)).toBe(false);
    expect(isActive(a2.refreshToken)).toBe(false);
    expect(isActive(b1.refreshToken)).toBe(true);
  });

  it('everywhere exige un token vigente: uno ya canjeado no cierra las demás sesiones', async () => {
    const old = await startSession();
    const other = await startSession();
    await renew(old.refreshToken); // `old` queda canjeado

    expect((await logoutWith({ refreshToken: old.refreshToken, everywhere: true })).status).toBe(204);
    expect(isActive(other.refreshToken)).toBe(true);
  });

  it('valida el cuerpo: sin token 400, everywhere que no es booleano 400, Content-Type incorrecto 415', async () => {
    expect((await logoutWith({})).status).toBe(400);
    expect((await logoutWith({ refreshToken: 'x', everywhere: 'si' })).status).toBe(400);
    expect((await logoutWith('refreshToken=x', { 'content-type': 'text/plain' })).status).toBe(415);
    expect((await logoutWith('{roto')).status).toBe(400);
  });

  it('limitación documentada: el access token ya emitido sigue sirviendo hasta que vence (15 min)', async () => {
    const { accessToken, refreshToken } = await startSession();
    await logoutWith({ refreshToken });
    expect((await profile(accessToken)).status).toBe(200);
  });

  it('un access token no sirve para cerrar sesiones ajenas: con él no se revoca nada', async () => {
    const victim = await startSession('ana@example.com');
    const attacker = await startSession('beto@example.com');
    const forged = generateAccessToken({ userId: victim.user.id, email: victim.user.email, role: 'USER' });
    await logoutWith({ refreshToken: forged, everywhere: true });
    await logoutWith({ refreshToken: attacker.refreshToken, everywhere: true });
    expect(isActive(victim.refreshToken)).toBe(true);
  });
});

describe('límite de sesiones activas por usuario', () => {
  it(`la sesión número ${MAX_ACTIVE_SESSIONS + 1} desplaza a la más antigua`, async () => {
    const sessions: Session[] = [];
    for (let i = 0; i < MAX_ACTIVE_SESSIONS; i++) sessions.push(await startSession());
    expect(activeRows()).toHaveLength(MAX_ACTIVE_SESSIONS);

    const newest = await startSession();
    expect(activeRows()).toHaveLength(MAX_ACTIVE_SESSIONS);
    expect((await refreshWith(sessions[0].refreshToken)).status).toBe(401);
    expect((await refreshWith(sessions[1].refreshToken)).status).toBe(200);
    expect((await refreshWith(newest.refreshToken)).status).toBe(200);
  }, 30_000);

  it('renovar cuenta como uso: se desplaza la sesión que hace más tiempo no se renueva', async () => {
    const sessions: Session[] = [];
    for (let i = 0; i < MAX_ACTIVE_SESSIONS; i++) sessions.push(await startSession());
    const renewed = await renew(sessions[0].refreshToken);

    await startSession();
    expect((await refreshWith(sessions[1].refreshToken)).status).toBe(401);
    expect((await refreshWith(renewed.refreshToken)).status).toBe(200);
  }, 30_000);

  it('el límite es por usuario: las sesiones de otro no cuentan', async () => {
    for (let i = 0; i < MAX_ACTIVE_SESSIONS; i++) await startSession('ana@example.com');
    const beto = await startSession('beto@example.com');
    expect(activeRows()).toHaveLength(MAX_ACTIVE_SESSIONS + 1);
    expect(isActive(beto.refreshToken)).toBe(true);
  }, 30_000);

  it('al iniciar sesión se borran los refresh tokens vencidos, de cualquier usuario', async () => {
    const old = await startSession('beto@example.com');
    rowOf(old.refreshToken).expiresAt = new Date(Date.now() - 1_000);

    await startSession('ana@example.com');
    expect(tokens().some((t) => t.jti === jtiOf(old.refreshToken))).toBe(false);
    expect(tokens()).toHaveLength(1);
  });
});

describe('registros (logs) de sesión', () => {
  it('login, renovación, logout y reutilización dejan ids, nunca tokens, emails ni contraseñas', async () => {
    const first = await startSession();
    const second = await renew(first.refreshToken);
    await refreshWith(first.refreshToken); // reutilización
    await logoutWith({ refreshToken: second.refreshToken, everywhere: true });

    const logs = allLogs().join('\n');
    expect(logs).toContain(first.user.id);
    for (const secret of [first.refreshToken, first.accessToken, second.refreshToken, second.accessToken, 'ana@example.com', PASSWORD]) {
      expect(logs).not.toContain(secret);
    }
  });
});

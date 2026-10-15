import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { prisma } from '@/lib/db';
import { MAX_ACTIVE_SESSIONS } from '@/lib/refresh-tokens';
import { POST as register } from '@/app/api/auth/register/route';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as refresh } from '@/app/api/auth/refresh/route';
import { POST as logout } from '@/app/api/auth/logout/route';
import { GET as me } from '@/app/api/users/me/route';
import { GET as listUsers } from '@/app/api/admin/users/route';
import { bearer, jsonRequest, readJson } from '../helpers/http';

// Pruebas de integración: los route handlers reales contra PostgreSQL real, con Prisma real.
// Complementan a las pruebas unitarias (que usan un Prisma falso) en lo que solo la base puede
// confirmar: el UPDATE condicional bajo concurrencia, el rollback de la transacción, la cascada,
// el índice único de email y la búsqueda sin distinguir mayúsculas.

vi.mock('@/lib/logger', () => ({
  log: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  logger: {},
}));
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, randomUUID: vi.fn(() => actual.randomUUID()) };
});

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) {
  throw new Error('Definí TEST_DATABASE_URL con una base PostgreSQL de pruebas (con las migraciones aplicadas).');
}
// Cada test vacía las tablas: se niega a correr contra cualquier base cuyo nombre no diga "test".
if (!/test/i.test(new URL(databaseUrl).pathname)) {
  throw new Error('TEST_DATABASE_URL tiene que apuntar a una base descartable cuyo nombre incluya "test".');
}

const ctx = {};
const PASSWORD = 'Passw0rdOk';
const HASH = bcrypt.hashSync(PASSWORD, 10);

const post = (path: string, body: unknown) => jsonRequest(path, { body });
const signUp = (email: string) => register(post('/api/auth/register', { email, password: PASSWORD }), ctx);
const signIn = (email: string) => login(post('/api/auth/login', { email, password: PASSWORD }), ctx);
const refreshWith = (refreshToken: string) => refresh(post('/api/auth/refresh', { refreshToken }), ctx);
const logoutWith = (body: unknown) => logout(post('/api/auth/logout', body), ctx);
const profile = (token: string) => me(jsonRequest('/api/users/me', { method: 'GET', headers: bearer(token) }), ctx);
const adminList = (token: string) => listUsers(jsonRequest('/api/admin/users', { method: 'GET', headers: bearer(token) }), ctx);

const jtiOf = (token: string) => (jwt.decode(token) as jwt.JwtPayload).jti as string;
const rowOf = (token: string) => prisma.refreshToken.findUniqueOrThrow({ where: { jti: jtiOf(token) } });
const liveTokens = (userId: string) =>
  prisma.refreshToken.count({ where: { userId, revokedAt: null, expiresAt: { gt: new Date() } } });

async function createUser(email: string, role: 'USER' | 'ADMIN' = 'USER') {
  return prisma.user.create({ data: { email, password: HASH, name: 'Test', role } });
}

async function startSession(email = 'ana@example.com') {
  if (!(await prisma.user.findUnique({ where: { email } }))) await createUser(email);
  return (await readJson(await signIn(email))) as { accessToken: string; refreshToken: string; user: { id: string } };
}

beforeAll(async () => {
  await prisma.$queryRaw`SELECT 1`;
});
beforeEach(async () => {
  await prisma.$executeRawUnsafe('TRUNCATE TABLE "refresh_tokens", "users" CASCADE');
  vi.clearAllMocks();
});
afterAll(async () => {
  await prisma.$disconnect();
});

describe('flujo completo contra PostgreSQL', () => {
  it('registro, perfil, renovación y reutilización: la sesión entera queda revocada en la base', async () => {
    const res = await signUp('Nueva@Example.com');
    const created = await readJson(res);
    expect(res.status).toBe(201);
    expect((await profile(created.accessToken)).status).toBe(200);

    const renewed = await readJson(await refreshWith(created.refreshToken));
    expect((await profile(renewed.accessToken)).status).toBe(200);
    expect((await rowOf(created.refreshToken)).revokedAt).not.toBeNull();

    expect((await refreshWith(created.refreshToken)).status).toBe(401); // reutilización
    expect((await refreshWith(renewed.refreshToken)).status).toBe(401);
    expect(await liveTokens(created.user.id)).toBe(0);
    expect(await prisma.refreshToken.count({ where: { userId: created.user.id } })).toBe(2);
  });

  it('en la tabla queda el jti y las fechas, no el token', async () => {
    const { refreshToken } = await startSession();
    const rows = await prisma.$queryRawUnsafe<Record<string, unknown>[]>('SELECT * FROM "refresh_tokens"');
    expect(rows).toHaveLength(1);
    expect(Object.keys(rows[0]).sort()).toEqual(['createdAt', 'expiresAt', 'familyId', 'jti', 'revokedAt', 'sessionExpiresAt', 'userId']);
    expect(JSON.stringify(rows)).not.toContain(refreshToken);
    const claims = jwt.decode(refreshToken) as jwt.JwtPayload;
    expect((await rowOf(refreshToken)).expiresAt.getTime()).toBe(claims.exp! * 1000);
  });
});

describe('canje de refresh tokens bajo concurrencia real', () => {
  it('8 canjes simultáneos del mismo token: exactamente uno gana y la sesión queda cerrada', async () => {
    const { refreshToken, user } = await startSession();

    const responses = await Promise.all(Array.from({ length: 8 }, () => refreshWith(refreshToken)));
    const statuses = responses.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 401, 401, 401, 401, 401, 401, 401]);

    // El token que recibió el ganador ya quedó revocado por quienes perdieron.
    const winner = await readJson(responses.find((r) => r.status === 200)!);
    expect((await refreshWith(winner.refreshToken)).status).toBe(401);
    expect(await liveTokens(user.id)).toBe(0);
  });

  it('si falla la emisión del token nuevo, la transacción se deshace y el token anterior sigue vigente', async () => {
    const { refreshToken, user } = await startSession();
    // Fuerza que el jti del token nuevo choque con uno existente: el INSERT falla dentro de la transacción.
    vi.mocked(randomUUID).mockReturnValueOnce(jtiOf(refreshToken) as ReturnType<typeof randomUUID>);

    const failed = await refreshWith(refreshToken);
    expect(failed.status).toBe(500);
    expect((await rowOf(refreshToken)).revokedAt).toBeNull();
    expect(await liveTokens(user.id)).toBe(1);

    expect((await refreshWith(refreshToken)).status).toBe(200);
  });
});

describe('sesiones y limpieza', () => {
  it(`la sesión ${MAX_ACTIVE_SESSIONS + 1} desplaza a la que hace más tiempo no se renueva`, async () => {
    const sessions = [];
    for (let i = 0; i < MAX_ACTIVE_SESSIONS; i++) sessions.push(await startSession());
    const renewed = await readJson(await refreshWith(sessions[0].refreshToken)); // la 0 se usa: pasa a ser la más reciente

    const newest = await startSession();
    expect(await liveTokens(newest.user.id)).toBe(MAX_ACTIVE_SESSIONS);
    expect((await refreshWith(sessions[1].refreshToken)).status).toBe(401); // la desplazada
    expect((await refreshWith(renewed.refreshToken)).status).toBe(200);
    expect((await refreshWith(newest.refreshToken)).status).toBe(200);
  });

  it('al iniciar sesión se borran los refresh tokens vencidos de cualquier usuario', async () => {
    const other = await createUser('otra@example.com');
    const past = new Date(Date.now() - 60_000);
    await prisma.refreshToken.create({ data: { jti: 'vencido', familyId: 'f', userId: other.id, expiresAt: past, sessionExpiresAt: past } });

    await startSession();
    expect(await prisma.refreshToken.findUnique({ where: { jti: 'vencido' } })).toBeNull();
  });

  it('borrar un usuario borra sus refresh tokens (cascada en la base)', async () => {
    const { user } = await startSession();
    await startSession();
    expect(await prisma.refreshToken.count({ where: { userId: user.id } })).toBe(2);

    await prisma.user.delete({ where: { id: user.id } });
    expect(await prisma.refreshToken.count()).toBe(0);
  });

  it('logout cierra una sesión y logout everywhere cierra todas las del usuario, nada más', async () => {
    const phone = await startSession('ana@example.com');
    const laptop = await startSession('ana@example.com');
    const beto = await startSession('beto@example.com');

    expect((await logoutWith({ refreshToken: phone.refreshToken })).status).toBe(204);
    expect((await refreshWith(phone.refreshToken)).status).toBe(401);
    expect((await rowOf(laptop.refreshToken)).revokedAt).toBeNull();

    const fresh = await startSession('ana@example.com');
    expect((await logoutWith({ refreshToken: fresh.refreshToken, everywhere: true })).status).toBe(204);
    expect(await liveTokens(laptop.user.id)).toBe(0);
    expect(await liveTokens(beto.user.id)).toBe(1);
  });
});

describe('cuentas y roles contra la base real', () => {
  it('dos registros simultáneos del mismo email: uno recibe 201 y el otro 409 (índice único real)', async () => {
    const results = await Promise.all([signUp('carrera@example.com'), signUp('carrera@example.com')]);
    expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(await prisma.user.count()).toBe(1);
  });

  it('una cuenta anterior guardada con mayúsculas puede entrar y el comodín _ no confunde cuentas', async () => {
    await createUser('Vieja@Example.com');
    await createUser('Ab@Example.com');

    expect((await signIn('vieja@example.com')).status).toBe(200);
    expect((await signIn('a_@example.com')).status).toBe(401);
    expect((await signUp('VIEJA@example.com')).status).toBe(409);
  });

  it('un admin degradado pierde el acceso al instante (el rol se lee de la base)', async () => {
    const admin = await createUser('admin@example.com', 'ADMIN');
    const { accessToken } = await readJson(await signIn('admin@example.com'));
    expect((await adminList(accessToken)).status).toBe(200);

    await prisma.user.update({ where: { id: admin.id }, data: { role: 'USER' } });
    expect((await adminList(accessToken)).status).toBe(403);

    await prisma.user.delete({ where: { id: admin.id } });
    expect((await adminList(accessToken)).status).toBe(401);
  });
});

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { describe, expect, it, vi } from 'vitest';
import { log } from '@/lib/logger';
import { POST as register } from '@/app/api/auth/register/route';
import { POST as login } from '@/app/api/auth/login/route';
import { POST as refresh } from '@/app/api/auth/refresh/route';
import { GET as me } from '@/app/api/users/me/route';
import { dbState } from './helpers/db-state';
import { bearer, jsonRequest, readJson } from './helpers/http';
import { PASSWORD, seedUser } from './helpers/seed';

const ctx = {};

const signUp = (body: unknown, headers?: Record<string, string>) =>
  register(jsonRequest('/api/auth/register', { body, headers }), ctx);
const signIn = (body: unknown) => login(jsonRequest('/api/auth/login', { body }), ctx);
const refreshWith = (refreshToken: string) => refresh(jsonRequest('/api/auth/refresh', { body: { refreshToken } }), ctx);
const profile = (token: string) => me(jsonRequest('/api/users/me', { method: 'GET', headers: bearer(token) }), ctx);

const allLogs = () => [log.info, log.warn, log.error, log.debug].flatMap((fn) => vi.mocked(fn).mock.calls.map((call) => String(call[0])));

describe('POST /api/auth/register', () => {
  it('crea la cuenta, devuelve tokens y nunca la contraseña', async () => {
    const res = await signUp({ email: 'ana@example.com', password: PASSWORD, name: 'Ana Pérez' });
    const body = await readJson(res);

    expect(res.status).toBe(201);
    expect(body.user).toMatchObject({ email: 'ana@example.com', name: 'Ana Pérez', role: 'USER' });
    expect(body.user).not.toHaveProperty('password');
    expect(typeof body.accessToken).toBe('string');
    expect(typeof body.refreshToken).toBe('string');
    expect(dbState.prisma.users[0].password).not.toBe(PASSWORD);
    expect(dbState.prisma.users[0].password).toMatch(/^\$2[aby]\$10\$/);
  });

  it('normaliza el email: sin espacios y en minúsculas', async () => {
    const res = await signUp({ email: '  Ana@Example.COM ', password: PASSWORD });
    expect(res.status).toBe(201);
    expect(dbState.prisma.users[0].email).toBe('ana@example.com');
  });

  it('no permite cuentas duplicadas que solo difieren en mayúsculas', async () => {
    expect((await signUp({ email: 'Ana@Example.com', password: PASSWORD })).status).toBe(201);
    const second = await signUp({ email: 'ana@example.com', password: PASSWORD });
    expect(second.status).toBe(409);
    expect(dbState.prisma.users).toHaveLength(1);
  });

  it('detecta también una cuenta anterior guardada con mayúsculas', async () => {
    await dbState.prisma.user.create({ data: { email: 'Vieja@Example.com', password: 'x' } });
    expect((await signUp({ email: 'vieja@example.com', password: PASSWORD })).status).toBe(409);
  });

  it('dos registros simultáneos del mismo email: el perdedor recibe 409 y no un 500', async () => {
    const create = dbState.prisma.user.create;
    await create({ data: { email: 'carrera@example.com', password: 'x' } });
    // Simula que ambos pasaron la búsqueda previa antes de que el otro insertara.
    vi.spyOn(dbState.prisma.user, 'findUnique').mockResolvedValueOnce(null);
    vi.spyOn(dbState.prisma.user, 'findFirst').mockResolvedValueOnce(null);
    const res = await signUp({ email: 'carrera@example.com', password: PASSWORD });
    expect(res.status).toBe(409);
  });

  it('ignora campos que el cliente no debe controlar (role, id, password hasheada)', async () => {
    const res = await signUp({ email: 'intruso@example.com', password: PASSWORD, role: 'ADMIN', id: 'forzado', createdAt: '2000-01-01' });
    const body = await readJson(res);
    expect(res.status).toBe(201);
    expect(body.user.role).toBe('USER');
    expect(body.user.id).not.toBe('forzado');
    expect(dbState.prisma.users[0].role).toBe('USER');
  });

  it.each([
    ['sin mayúscula', 'passw0rdok'],
    ['sin minúscula', 'PASSW0RDOK'],
    ['sin número', 'PasswordOk'],
    ['demasiado corta', 'Pa1'],
    ['de más de 72 bytes (bcrypt la truncaría en silencio)', `Aa1${'x'.repeat(70)}`],
    ['de más de 72 bytes en UTF-8 aunque tenga menos de 72 caracteres', `Aa1${'ñ'.repeat(37)}`],
  ])('rechaza una contraseña %s', async (_label, password) => {
    const res = await signUp({ email: 'x@example.com', password });
    expect(res.status).toBe(400);
    expect(dbState.prisma.users).toHaveLength(0);
  });

  it('acepta una contraseña de exactamente 72 bytes', async () => {
    const res = await signUp({ email: 'justa@example.com', password: `Aa1${'x'.repeat(69)}` });
    expect(res.status).toBe(201);
  });

  it.each([
    ['email de más de 254 caracteres', { email: `${'a'.repeat(250)}@example.com`, password: PASSWORD }],
    ['email sin formato', { email: 'no-es-un-email', password: PASSWORD }],
    ['nombre de más de 100 caracteres', { email: 'x@example.com', password: PASSWORD, name: 'n'.repeat(101) }],
    ['nombre de un solo caracter', { email: 'x@example.com', password: PASSWORD, name: 'n' }],
    ['tipos equivocados', { email: 123, password: ['a'] }],
    ['cuerpo que no es un objeto', [1, 2, 3]],
  ])('rechaza %s con 400', async (_label, body) => {
    const res = await signUp(body);
    expect(res.status).toBe(400);
    expect((await readJson(res)).error).toBe('Validation failed');
  });

  it('JSON roto responde 400 (no 500)', async () => {
    const res = await signUp('{esto no es json');
    expect(res.status).toBe(400);
    expect(await readJson(res)).toEqual({ error: 'Invalid JSON' });
  });

  it('exige Content-Type: application/json (415)', async () => {
    const res = await signUp('email=a@b.co&password=x', { 'content-type': 'application/x-www-form-urlencoded' });
    expect(res.status).toBe(415);
  });

  it('corta los cuerpos grandes: declarados (413) y también sin Content-Length', async () => {
    const big = JSON.stringify({ email: 'x@example.com', password: `Aa1${'y'.repeat(2_000_000)}` });
    expect((await signUp(big)).status).toBe(413);
    expect((await signUp(big, { 'content-length': String(big.length) })).status).toBe(413);
    expect(dbState.prisma.users).toHaveLength(0);
  });

  it('en los logs queda el id, no el email, la contraseña ni los tokens', async () => {
    const res = await signUp({ email: 'privado@example.com', password: PASSWORD });
    const body = await readJson(res);
    const logs = allLogs().join('\n');
    expect(logs).toContain(body.user.id);
    expect(logs).not.toContain('privado@example.com');
    expect(logs).not.toContain(PASSWORD);
    expect(logs).not.toContain(body.accessToken);
    expect(logs).not.toContain(body.refreshToken);
  });
});

describe('POST /api/auth/login', () => {
  it('devuelve usuario y tokens con credenciales correctas', async () => {
    await seedUser('ana@example.com');
    const res = await signIn({ email: 'ana@example.com', password: PASSWORD });
    const body = await readJson(res);
    expect(res.status).toBe(200);
    expect(body.user).toMatchObject({ email: 'ana@example.com', role: 'USER' });
    expect(body.user).not.toHaveProperty('password');
    expect(typeof body.accessToken).toBe('string');
    expect(typeof body.refreshToken).toBe('string');
  });

  it('ignora mayúsculas y espacios del email', async () => {
    await seedUser('ana@example.com');
    expect((await signIn({ email: ' ANA@Example.com ', password: PASSWORD })).status).toBe(200);
  });

  it('permite entrar a una cuenta anterior guardada con mayúsculas', async () => {
    await seedUser('Vieja@Example.com');
    expect((await signIn({ email: 'vieja@example.com', password: PASSWORD })).status).toBe(200);
  });

  it('el comodín _ del email no hace coincidir otra cuenta', async () => {
    await seedUser('Ab@Example.com');
    expect((await signIn({ email: 'a_@example.com', password: PASSWORD })).status).toBe(401);
  });

  it('mismo error para contraseña incorrecta y para email inexistente', async () => {
    await seedUser('ana@example.com');
    const wrongPassword = await signIn({ email: 'ana@example.com', password: 'OtraClave123' });
    const unknownEmail = await signIn({ email: 'nadie@example.com', password: 'OtraClave123' });
    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(await readJson(wrongPassword)).toEqual(await readJson(unknownEmail));
  });

  it('con un email inexistente también se ejecuta bcrypt (contra un hash de relleno)', async () => {
    await seedUser('ana@example.com');
    const compare = vi.spyOn(bcrypt, 'compare');

    await signIn({ email: 'nadie@example.com', password: 'OtraClave123' });
    expect(compare).toHaveBeenCalledTimes(1);
    expect(String(compare.mock.calls[0][1])).toMatch(/^\$2[aby]\$10\$/);

    compare.mockClear();
    await signIn({ email: 'ana@example.com', password: 'OtraClave123' });
    expect(compare).toHaveBeenCalledTimes(1);
    compare.mockRestore();
  });

  it('el tiempo de respuesta no depende de si el email existe', async () => {
    await seedUser('ana@example.com');
    const time = async (email: string) => {
      const start = performance.now();
      await signIn({ email, password: 'OtraClave123' });
      return performance.now() - start;
    };
    const median = (values: number[]) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];

    await time('ana@example.com');
    await time('nadie@example.com');
    const known: number[] = [];
    const unknown: number[] = [];
    for (let i = 0; i < 7; i++) {
      known.push(await time('ana@example.com'));
      unknown.push(await time('nadie@example.com'));
    }
    // Antes del arreglo la relación era ~180 a 1 (98 ms contra 0,5 ms).
    expect(median(known) / median(unknown)).toBeLessThan(3);
    expect(median(unknown) / median(known)).toBeLessThan(3);
  }, 30_000);

  it('JSON roto responde 400, Content-Type incorrecto 415 y contraseña gigante 400', async () => {
    expect((await signIn('{roto')).status).toBe(400);
    expect((await login(jsonRequest('/api/auth/login', { body: 'a=b', headers: { 'content-type': 'text/plain' } }), ctx)).status).toBe(415);
    expect((await signIn({ email: 'ana@example.com', password: 'x'.repeat(5000) })).status).toBe(400);
  });

  it('los logs tienen el id del usuario y no el email ni la contraseña', async () => {
    const user = await seedUser('ana@example.com');
    await signIn({ email: 'ana@example.com', password: PASSWORD });
    const logs = allLogs().join('\n');
    expect(logs).toContain(user.id);
    expect(logs).not.toContain('ana@example.com');
    expect(logs).not.toContain(PASSWORD);
  });
});

describe('POST /api/auth/refresh', () => {
  async function session(email = 'ana@example.com') {
    await seedUser(email);
    return readJson(await signIn({ email, password: PASSWORD }));
  }

  it('canjea un refresh token válido por un par nuevo', async () => {
    const { refreshToken } = await session();
    const res = await refreshWith(refreshToken);
    const body = await readJson(res);
    expect(res.status).toBe(200);
    expect(typeof body.accessToken).toBe('string');
    expect(body.refreshToken).not.toBe(refreshToken); // distinto aunque se emita en el mismo segundo
    expect((await profile(body.accessToken)).status).toBe(200);
  });

  it('rechaza un access token, basura y un token firmado con otro secreto', async () => {
    const { accessToken } = await session();
    expect((await refreshWith(accessToken)).status).toBe(401);
    expect((await refreshWith('basura')).status).toBe(401);
    const forged = jwt.sign({ userId: 'x', email: 'x@y.zz', role: 'ADMIN' }, 'change-this-in-production-too', { expiresIn: '7d' });
    expect((await refreshWith(forged)).status).toBe(401);
  });

  it('si el usuario ya no existe responde el mismo error genérico que con un token inválido', async () => {
    const { refreshToken, user } = await session();
    await dbState.prisma.user.delete({ where: { id: user.id } });
    const gone = await refreshWith(refreshToken);
    const invalid = await refreshWith('basura');
    expect(gone.status).toBe(401);
    expect(await readJson(gone)).toEqual(await readJson(invalid));
  });

  it('el rol del access token nuevo sale de la base, no del refresh token', async () => {
    const { refreshToken, user } = await session();
    await dbState.prisma.user.update({ where: { id: user.id }, data: { role: 'ADMIN' } });
    const body = await readJson(await refreshWith(refreshToken));
    expect((jwt.decode(body.accessToken) as jwt.JwtPayload).role).toBe('ADMIN');
  });

  it('JSON roto responde 400', async () => {
    expect((await refresh(jsonRequest('/api/auth/refresh', { body: '{roto' }), ctx)).status).toBe(400);
  });
});

describe('GET /api/users/me', () => {
  it('devuelve el perfil con un access token válido', async () => {
    await seedUser('ana@example.com');
    const { accessToken } = await readJson(await signIn({ email: 'ana@example.com', password: PASSWORD }));
    const res = await profile(accessToken);
    expect(res.status).toBe(200);
    expect((await readJson(res)).user.email).toBe('ana@example.com');
  });

  it('401 sin token, con un refresh token o con un token firmado por otro', async () => {
    await seedUser('ana@example.com');
    const { refreshToken } = await readJson(await signIn({ email: 'ana@example.com', password: PASSWORD }));
    expect((await me(jsonRequest('/api/users/me', { method: 'GET' }), ctx)).status).toBe(401);
    expect((await profile(refreshToken)).status).toBe(401);
    expect((await profile(jwt.sign({ userId: 'x' }, 'otro-secreto-cualquiera-0123456789abcdef'))).status).toBe(401);
  });

  it('404 si la cuenta fue eliminada', async () => {
    const user = await seedUser('ana@example.com');
    const { accessToken } = await readJson(await signIn({ email: 'ana@example.com', password: PASSWORD }));
    await dbState.prisma.user.delete({ where: { id: user.id } });
    expect((await profile(accessToken)).status).toBe(404);
  });
});

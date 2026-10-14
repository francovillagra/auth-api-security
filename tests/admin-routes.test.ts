import jwt from 'jsonwebtoken';
import { describe, expect, it, vi } from 'vitest';
import { log } from '@/lib/logger';
import { generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { POST as login } from '@/app/api/auth/login/route';
import { GET as listUsers } from '@/app/api/admin/users/route';
import { PATCH as changeRole } from '@/app/api/admin/users/[id]/role/route';
import { dbState } from './helpers/db-state';
import { bearer, jsonRequest, readJson } from './helpers/http';
import { PASSWORD, seedUser } from './helpers/seed';

async function tokenFor(email: string) {
  const res = await login(jsonRequest('/api/auth/login', { body: { email, password: PASSWORD } }), {});
  return (await readJson(res)).accessToken as string;
}

const list = (token?: string) =>
  listUsers(jsonRequest('/api/admin/users', { method: 'GET', headers: token ? bearer(token) : {} }), {});

const patchRole = (id: string, token: string | undefined, body: unknown, headers: Record<string, string> = {}) =>
  changeRole(
    jsonRequest(`/api/admin/users/${id}/role`, { method: 'PATCH', body, headers: { ...(token ? bearer(token) : {}), ...headers } }),
    { params: Promise.resolve({ id }) },
  );

describe('GET /api/admin/users', () => {
  it('un ADMIN recibe la lista sin contraseñas', async () => {
    await seedUser('admin@example.com', 'ADMIN');
    await seedUser('ana@example.com');
    const res = await list(await tokenFor('admin@example.com'));
    const body = await readJson(res);

    expect(res.status).toBe(200);
    expect(body.total).toBe(2);
    expect(JSON.stringify(body)).not.toContain('password');
    expect(body.requestedBy).toMatchObject({ email: 'admin@example.com', role: 'ADMIN' });
  });

  it('401 sin token, con basura o con un refresh token', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    expect((await list()).status).toBe(401);
    expect((await list('basura')).status).toBe(401);
    expect((await list(generateRefreshToken({ userId: admin.id, email: admin.email, role: 'ADMIN' }))).status).toBe(401);
  });

  it('un USER recibe 403 con un mensaje que no revela roles', async () => {
    await seedUser('ana@example.com');
    const res = await list(await tokenFor('ana@example.com'));
    const body = await readJson(res);
    expect(res.status).toBe(403);
    expect(body.error).toBe('Forbidden');
    expect(JSON.stringify(body)).not.toMatch(/ADMIN|USER|rol/i);
  });

  it('un admin degradado pierde el acceso al instante, aunque su token siga vigente', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    const token = await tokenFor('admin@example.com');
    expect((await list(token)).status).toBe(200);

    await dbState.prisma.user.update({ where: { id: admin.id }, data: { role: 'USER' } });
    expect((await list(token)).status).toBe(403);
  });

  it('un admin eliminado pierde el acceso al instante', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    const token = await tokenFor('admin@example.com');
    await dbState.prisma.user.delete({ where: { id: admin.id } });
    expect((await list(token)).status).toBe(401);
  });

  it('no alcanza con un token que dice ADMIN si la base dice USER (token con el rol adulterado dentro de un token válido)', async () => {
    const user = await seedUser('ana@example.com');
    // Token legítimo (firmado por la API) cuyo rol en el payload es ADMIN pero la base dice USER:
    // es lo que pasa tras una degradación. El rol manda lo que dice la base.
    const stale = generateAccessToken({ userId: user.id, email: user.email, role: 'ADMIN' });
    expect((await list(stale)).status).toBe(403);
  });

  it('un error inesperado responde 500 genérico y queda registrado', async () => {
    await seedUser('admin@example.com', 'ADMIN');
    const token = await tokenFor('admin@example.com');
    vi.spyOn(dbState.prisma.user, 'findMany').mockRejectedValueOnce(new Error('connection refused postgres://user:secret@db'));

    const res = await list(token);
    expect(res.status).toBe(500);
    expect(await readJson(res)).toEqual({ error: 'Internal server error' });
    expect(vi.mocked(log.error)).toHaveBeenCalled();
  });

  it('un token válido de un usuario que no existe (id inventado) recibe 401', async () => {
    const ghost = jwt.sign(
      { userId: 'no-existe', email: 'ghost@example.com', role: 'ADMIN' },
      process.env.JWT_SECRET!,
      { expiresIn: '5m', issuer: 'auth-api-security', audience: 'auth-api-security:access' },
    );
    expect((await list(ghost)).status).toBe(401);
  });
});

describe('PATCH /api/admin/users/:id/role', () => {
  it('un ADMIN cambia el rol de otro usuario', async () => {
    await seedUser('admin@example.com', 'ADMIN');
    const target = await seedUser('ana@example.com');
    const res = await patchRole(target.id, await tokenFor('admin@example.com'), { role: 'ADMIN' });
    const body = await readJson(res);

    expect(res.status).toBe(200);
    expect(body.user).toMatchObject({ id: target.id, role: 'ADMIN' });
    expect(dbState.prisma.users.find((u) => u.id === target.id)!.role).toBe('ADMIN');
  });

  it('401 sin token y 403 para un USER; el rol no cambia', async () => {
    const target = await seedUser('ana@example.com');
    expect((await patchRole(target.id, undefined, { role: 'ADMIN' })).status).toBe(401);
    expect((await patchRole(target.id, await tokenFor('ana@example.com'), { role: 'ADMIN' })).status).toBe(403);
    expect(dbState.prisma.users[0].role).toBe('USER');
  });

  it('un admin degradado ya no puede cambiar roles', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    const target = await seedUser('ana@example.com');
    const token = await tokenFor('admin@example.com');
    await dbState.prisma.user.update({ where: { id: admin.id }, data: { role: 'USER' } });
    expect((await patchRole(target.id, token, { role: 'ADMIN' })).status).toBe(403);
    expect(dbState.prisma.users.find((u) => u.id === target.id)!.role).toBe('USER');
  });

  it('un admin no puede quitarse el rol a sí mismo', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    const res = await patchRole(admin.id, await tokenFor('admin@example.com'), { role: 'USER' });
    expect(res.status).toBe(400);
    expect(dbState.prisma.users[0].role).toBe('ADMIN');
  });

  it('404 si el usuario no existe', async () => {
    await seedUser('admin@example.com', 'ADMIN');
    expect((await patchRole('no-existe', await tokenFor('admin@example.com'), { role: 'ADMIN' })).status).toBe(404);
  });

  it.each([
    ['rol inventado', { role: 'SUPERADMIN' }],
    ['rol en minúsculas', { role: 'admin' }],
    ['sin rol', {}],
    ['tipo equivocado', { role: 1 }],
  ])('400 con %s', async (_label, body) => {
    await seedUser('admin@example.com', 'ADMIN');
    const target = await seedUser('ana@example.com');
    const res = await patchRole(target.id, await tokenFor('admin@example.com'), body);
    expect(res.status).toBe(400);
    expect(dbState.prisma.users.find((u) => u.id === target.id)!.role).toBe('USER');
  });

  it('JSON roto responde 400 y Content-Type incorrecto 415 (antes terminaba en una excepción sin atrapar)', async () => {
    await seedUser('admin@example.com', 'ADMIN');
    const target = await seedUser('ana@example.com');
    const token = await tokenFor('admin@example.com');
    expect((await patchRole(target.id, token, '{roto')).status).toBe(400);
    expect((await patchRole(target.id, token, 'role=ADMIN', { 'content-type': 'text/plain' })).status).toBe(415);
  });

  it('registra quién cambió qué usando ids, sin emails', async () => {
    const admin = await seedUser('admin@example.com', 'ADMIN');
    const target = await seedUser('ana@example.com');
    await patchRole(target.id, await tokenFor('admin@example.com'), { role: 'ADMIN' });
    const line = vi.mocked(log.info).mock.calls.map((c) => String(c[0])).find((m) => m.includes('changed role'));
    expect(line).toContain(admin.id);
    expect(line).toContain(target.id);
    expect(line).not.toContain('@example.com');
  });
});

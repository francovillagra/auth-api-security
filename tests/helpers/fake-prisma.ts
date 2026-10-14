import type { Role } from '@prisma/client';

/**
 * Prisma falso en memoria con el subconjunto que usa la API. Reproduce lo que importa para las pruebas de
 * seguridad: el índice único de email (P2002), `select` y la búsqueda sin distinguir mayúsculas.
 */
export interface FakeUser {
  id: string;
  email: string;
  password: string;
  name: string | null;
  role: Role;
  createdAt: Date;
  updatedAt: Date;
}

type Select = Record<string, boolean> | undefined;
type Where = { id?: string; email?: string | { equals: string; mode?: 'insensitive' } };

function pick<T extends object>(row: T, select: Select): Partial<T> {
  if (!select) return { ...row };
  return Object.fromEntries(Object.entries(select).filter(([, on]) => on).map(([key]) => [key, (row as Record<string, unknown>)[key]])) as Partial<T>;
}

function matches(user: FakeUser, where: Where): boolean {
  if (where.id !== undefined && user.id !== where.id) return false;
  if (where.email !== undefined) {
    if (typeof where.email === 'string') return user.email === where.email;
    const { equals, mode } = where.email;
    if (mode !== 'insensitive') return user.email === equals;
    // Peor caso: PostgreSQL compara con ILIKE, donde `_` y `%` son comodines. El código de la app
    // debe confirmar la coincidencia por su cuenta.
    const pattern = equals.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/_/g, '.').replace(/%/g, '.*');
    return new RegExp(`^${pattern}$`, 'i').test(user.email);
  }
  return true;
}

export function createFakePrisma() {
  const users: FakeUser[] = [];
  let counter = 0;

  const user = {
    async findUnique({ where, select }: { where: Where; select?: Select }) {
      const found = users.find((u) => matches(u, where));
      return found ? pick(found, select) : null;
    },
    async findFirst({ where, select }: { where: Where; select?: Select }) {
      const found = users.find((u) => matches(u, where));
      return found ? pick(found, select) : null;
    },
    async create({ data, select }: { data: { email: string; password: string; name?: string | null; role?: Role }; select?: Select }) {
      if (users.some((u) => u.email === data.email)) throw Object.assign(new Error('Unique constraint failed on the fields: (`email`)'), { code: 'P2002' });
      const now = new Date();
      const row: FakeUser = { id: `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`, email: data.email, password: data.password, name: data.name ?? null, role: data.role ?? 'USER', createdAt: now, updatedAt: now };
      users.push(row);
      return pick(row, select);
    },
    async update({ where, data, select }: { where: Where; data: Partial<FakeUser>; select?: Select }) {
      const row = users.find((u) => matches(u, where));
      if (!row) throw Object.assign(new Error('Record to update not found.'), { code: 'P2025' });
      Object.assign(row, data, { updatedAt: new Date() });
      return pick(row, select);
    },
    async findMany({ select }: { select?: Select; orderBy?: unknown } = {}) {
      return [...users].reverse().map((u) => pick(u, select));
    },
    async delete({ where }: { where: Where }) {
      const index = users.findIndex((u) => matches(u, where));
      if (index === -1) throw Object.assign(new Error('Record to delete does not exist.'), { code: 'P2025' });
      return users.splice(index, 1)[0];
    },
  };

  return { users, user };
}

export type FakePrisma = ReturnType<typeof createFakePrisma>;

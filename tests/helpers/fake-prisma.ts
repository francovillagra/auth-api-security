import type { Role } from '@prisma/client';

/**
 * Prisma falso en memoria con el subconjunto que usa la API. Reproduce lo que importa para las pruebas de
 * seguridad: el índice único de email (P2002), `select`, la búsqueda sin distinguir mayúsculas, los
 * `updateMany` condicionales (la base del canje de refresh tokens), el borrado en cascada y las
 * transacciones interactivas (que se serializan y se deshacen si fallan).
 *
 * Un filtro que el falso no entiende lanza un error en vez de ignorarse: así una condición mal escrita en
 * la app no puede pasar los tests por casualidad.
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

export interface FakeRefreshToken {
  jti: string;
  familyId: string;
  userId: string;
  expiresAt: Date;
  sessionExpiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
}

type Select = Record<string, boolean> | undefined;
type Where = { id?: string; email?: string | { equals: string; mode?: 'insensitive' } };
type TokenWhere = {
  jti?: string | { in: string[] };
  familyId?: string;
  userId?: string;
  revokedAt?: null;
  expiresAt?: { gt?: Date; lt?: Date };
};
type TokenOrderBy = { createdAt: 'asc' | 'desc' } | Array<{ createdAt: 'asc' | 'desc' }>;

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

const TOKEN_FILTERS = new Set(['jti', 'familyId', 'userId', 'revokedAt', 'expiresAt']);

function matchesToken(row: FakeRefreshToken, where: TokenWhere = {}): boolean {
  for (const key of Object.keys(where)) {
    if (!TOKEN_FILTERS.has(key)) throw new Error(`fake-prisma: filtro no soportado en refreshToken: ${key}`);
  }
  if (where.revokedAt !== undefined && where.revokedAt !== null) throw new Error('fake-prisma: revokedAt solo admite null');

  if (where.jti !== undefined) {
    const ok = typeof where.jti === 'string' ? row.jti === where.jti : where.jti.in.includes(row.jti);
    if (!ok) return false;
  }
  if (where.familyId !== undefined && row.familyId !== where.familyId) return false;
  if (where.userId !== undefined && row.userId !== where.userId) return false;
  if (where.revokedAt === null && row.revokedAt !== null) return false;
  if (where.expiresAt?.gt && !(row.expiresAt.getTime() > where.expiresAt.gt.getTime())) return false;
  if (where.expiresAt?.lt && !(row.expiresAt.getTime() < where.expiresAt.lt.getTime())) return false;
  return true;
}

function sortTokens(rows: FakeRefreshToken[], orderBy: TokenOrderBy | undefined): FakeRefreshToken[] {
  if (!orderBy) return rows;
  const [first] = Array.isArray(orderBy) ? orderBy : [orderBy];
  const direction = first?.createdAt === 'desc' ? -1 : 1;
  // Array.prototype.sort es estable: con la misma fecha queda el orden de inserción.
  return [...rows].sort((a, b) => direction * (a.createdAt.getTime() - b.createdAt.getTime()));
}

function uniqueViolation(fields: string) {
  return Object.assign(new Error(`Unique constraint failed on the fields: (\`${fields}\`)`), { code: 'P2002' });
}

export function createFakePrisma() {
  const users: FakeUser[] = [];
  const refreshTokens: FakeRefreshToken[] = [];
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
      if (users.some((u) => u.email === data.email)) throw uniqueViolation('email');
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
      const [removed] = users.splice(index, 1);
      // onDelete: Cascade
      for (let i = refreshTokens.length - 1; i >= 0; i--) if (refreshTokens[i].userId === removed.id) refreshTokens.splice(i, 1);
      return removed;
    },
  };

  const refreshToken = {
    async create({ data }: { data: Omit<FakeRefreshToken, 'revokedAt' | 'createdAt'> & { revokedAt?: Date | null } }) {
      if (refreshTokens.some((t) => t.jti === data.jti)) throw uniqueViolation('jti');
      if (!users.some((u) => u.id === data.userId)) {
        throw Object.assign(new Error('Foreign key constraint failed on the field: `userId`'), { code: 'P2003' });
      }
      const row: FakeRefreshToken = { ...data, revokedAt: data.revokedAt ?? null, createdAt: new Date() };
      refreshTokens.push(row);
      return { ...row };
    },
    async findUnique({ where, select }: { where: { jti: string }; select?: Select }) {
      const found = refreshTokens.find((t) => t.jti === where.jti);
      return found ? pick(found, select) : null;
    },
    async findMany({ where, orderBy, select }: { where?: TokenWhere; orderBy?: TokenOrderBy; select?: Select } = {}) {
      return sortTokens(refreshTokens.filter((t) => matchesToken(t, where)), orderBy).map((t) => pick(t, select));
    },
    // Una sola pasada síncrona: comprobar y modificar sin ceder el turno es lo que en PostgreSQL
    // garantiza el bloqueo de fila de un UPDATE ... WHERE ... IS NULL.
    async updateMany({ where, data }: { where?: TokenWhere; data: Partial<Pick<FakeRefreshToken, 'revokedAt'>> }) {
      const rows = refreshTokens.filter((t) => matchesToken(t, where));
      for (const row of rows) Object.assign(row, data);
      return { count: rows.length };
    },
    async deleteMany({ where }: { where?: TokenWhere } = {}) {
      let count = 0;
      for (let i = refreshTokens.length - 1; i >= 0; i--) {
        if (matchesToken(refreshTokens[i], where)) {
          refreshTokens.splice(i, 1);
          count++;
        }
      }
      return { count };
    },
  };

  const base = { users, refreshTokens, user, refreshToken };

  /**
   * Transacción interactiva: las transacciones se ejecutan de a una (en PostgreSQL la segunda se
   * bloquearía en la fila que tocó la primera) y, si la función lanza, se deshacen sus cambios.
   * No modela el aislamiento completo ni lo que otras consultas hagan a la vez.
   */
  let transactionQueue: Promise<unknown> = Promise.resolve();
  function $transaction<T>(fn: (tx: typeof base) => Promise<T>): Promise<T> {
    const run = async () => {
      const before = refreshTokens.map((t) => ({ ...t }));
      try {
        return await fn(base);
      } catch (error) {
        refreshTokens.splice(0, refreshTokens.length, ...before);
        throw error;
      }
    };
    const result = transactionQueue.then(run, run);
    transactionQueue = result.catch(() => undefined);
    return result;
  }

  const client = { ...base, $transaction };

  return client;
}

export type FakePrisma = ReturnType<typeof createFakePrisma>;

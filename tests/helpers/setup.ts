import { beforeEach, vi } from 'vitest';
import { createFakePrisma } from './fake-prisma';
import { dbState } from './db-state';

// Los tests no usan una base real: `@/lib/db` devuelve un Prisma falso en memoria.
vi.mock('@/lib/db', async () => {
  const { dbState: state } = await import('./db-state');
  return {
    get prisma() {
      return state.prisma;
    },
  };
});

// El logger real escribe en consola; los tests solo necesitan poder inspeccionar qué se registra.
vi.mock('@/lib/logger', () => ({
  log: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
  logger: {},
}));

beforeEach(() => {
  dbState.prisma = createFakePrisma();
  vi.clearAllMocks();
});

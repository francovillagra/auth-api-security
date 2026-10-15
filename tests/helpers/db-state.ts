import type { FakePrisma } from './fake-prisma';

/** Base falsa compartida entre el mock de `@/lib/db` y los tests; se reinicia antes de cada test. */
export const dbState: { prisma: FakePrisma } = { prisma: undefined as unknown as FakePrisma };

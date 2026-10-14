import { prisma } from '@/lib/db';

/**
 * Busca un usuario por email (ya normalizado a minúsculas por el esquema Zod).
 *
 * Los emails nuevos se guardan siempre en minúsculas. Las cuentas creadas antes de la
 * normalización pueden estar guardadas con mayúsculas, así que si no hay coincidencia exacta
 * se busca sin distinguir mayúsculas y se confirma en código, porque `mode: 'insensitive'`
 * en PostgreSQL usa ILIKE y `_` o `%` actuarían como comodines.
 */
export async function findUserByEmail(email: string) {
  const exact = await prisma.user.findUnique({ where: { email } });
  if (exact) return exact;

  const legacy = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
  return legacy && legacy.email.toLowerCase() === email ? legacy : null;
}

/** `true` si el error es la violación del índice único de Prisma (P2002). */
export function isUniqueViolation(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'P2002';
}

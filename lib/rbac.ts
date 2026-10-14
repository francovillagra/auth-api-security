// lib/rbac.ts
//
// requireRole: helper para App Router que valida JWT Y verifica rol contra la base.
//
// Distinción CRÍTICA de seguridad:
//   401 Unauthorized → no hay token / token inválido o expirado / el usuario ya no existe
//   403 Forbidden    → token válido pero rol insuficiente ("sé quién sos, no podés")
//
// El rol NUNCA se toma del token: se lee de la base en cada pedido. Si un admin es degradado
// o eliminado, pierde el acceso de inmediato y no recién cuando vence su access token.
//
// Uso en una route.ts de App Router:
//
//   export const GET = withLogging(async (req: NextRequest) => {
//     const auth = await requireRole(req, [Role.ADMIN]);
//     if (auth instanceof NextResponse) return auth; // 401 o 403
//     const user = auth; // identidad confirmada contra la base
//     ...
//   });

import { NextRequest, NextResponse } from 'next/server';
import { Role } from '@prisma/client';
import { prisma } from '@/lib/db';
import { getAuthUser, TokenPayload } from './auth';

/**
 * Verifica autenticación y rol.
 * Devuelve la identidad actual del usuario (leída de la base) si todo está OK,
 * o un NextResponse (401/403) si hay que cortar el flujo.
 */
export async function requireRole(
  req: NextRequest,
  allowedRoles: Role[]
): Promise<TokenPayload | NextResponse> {
  // ─── 1. Autenticación: ¿hay token válido? ───────────────
  const claims = getAuthUser(req);
  const unauthorized = () =>
    NextResponse.json(
      { error: 'Unauthorized', message: 'Token de autenticación faltante, inválido o expirado.' },
      { status: 401 }
    );

  if (!claims) return unauthorized();

  // ─── 2. El usuario tiene que seguir existiendo; su rol actual es el de la base ─────
  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, email: true, role: true },
  });
  if (!user) return unauthorized();

  // ─── 3. Autorización: ¿el rol alcanza? (sin revelar roles ni permisos) ─────────────
  if (!allowedRoles.includes(user.role)) {
    return NextResponse.json({ error: 'Forbidden', message: 'No tenés permisos para realizar esta acción.' }, { status: 403 });
  }

  return { userId: user.id, email: user.email, role: user.role };
}

// Alias de conveniencia: solo exige estar autenticado (cualquier rol)
export function requireAuth(req: NextRequest): Promise<TokenPayload | NextResponse> {
  return requireRole(req, [Role.USER, Role.ADMIN]);
}

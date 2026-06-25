// lib/rbac.ts
//
// requireRole: helper para App Router que valida JWT Y verifica rol.
//
// Distinción CRÍTICA de seguridad:
//   401 Unauthorized → no hay token / token inválido o expirado ("no sé quién sos")
//   403 Forbidden    → token válido pero rol insuficiente ("sé quién sos, no podés")
//
// Uso en una route.ts de App Router:
//
//   export async function GET(req: NextRequest) {
//     const authResult = requireRole(req, ['ADMIN']);
//     if (authResult instanceof NextResponse) return authResult; // 401 o 403
//     const user = authResult; // TokenPayload ya validado
//     ...
//   }

import { NextRequest, NextResponse } from 'next/server';
import { Role } from '@prisma/client';
import { getAuthUser, TokenPayload } from './auth';

/**
 * Verifica autenticación y rol.
 * Devuelve el TokenPayload si todo está OK,
 * o un NextResponse (401/403) si hay que cortar el flujo.
 */
export function requireRole(
  req: NextRequest,
  allowedRoles: Role[]
): TokenPayload | NextResponse {
  // ─── 1. Autenticación: ¿hay token válido? ───────────────
  const user = getAuthUser(req);

  if (!user) {
    return NextResponse.json(
      {
        error: 'Unauthorized',
        message: 'Token de autenticación faltante, inválido o expirado.',
      },
      { status: 401 }
    );
  }

  // ─── 2. Autorización: ¿el rol alcanza? ──────────────────
  if (!allowedRoles.includes(user.role)) {
    return NextResponse.json(
      {
        error: 'Forbidden',
        message: `Se requiere uno de los siguientes roles: ${allowedRoles.join(', ')}. Tu rol actual es: ${user.role}.`,
      },
      { status: 403 }
    );
  }

  // ─── 3. Todo OK: devolver el usuario autenticado ────────
  return user;
}

// Alias de conveniencia: solo exige estar autenticado (cualquier rol)
export function requireAuth(req: NextRequest): TokenPayload | NextResponse {
  return requireRole(req, [Role.USER, Role.ADMIN]);
}

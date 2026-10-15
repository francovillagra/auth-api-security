// app/api/admin/users/route.ts
// GET /api/admin/users — lista todos los usuarios (sin exponer password)
// Protegido: solo ADMIN (el rol se confirma contra la base en cada pedido)
//   Sin token / usuario inexistente → 401
//   Token USER                      → 403
//   Token ADMIN                     → 200 con lista

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireRole } from '@/lib/rbac';
import { Role } from '@prisma/client';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

async function handler(req: NextRequest) {
  const authResult = await requireRole(req, [Role.ADMIN]);
  if (authResult instanceof NextResponse) return authResult; // 401 o 403

  const requestingUser = authResult;

  const users = await prisma.user.findMany({
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      createdAt: true,
      updatedAt: true,
      // password: false ← excluido explícitamente, nunca se expone
    },
    orderBy: { createdAt: 'desc' },
  });

  log.info(`Admin user list accessed by: ${requestingUser.userId}`);

  return NextResponse.json({
    users,
    total: users.length,
    requestedBy: {
      userId: requestingUser.userId,
      email: requestingUser.email,
      role: requestingUser.role,
    },
  });
}

export const GET = withLogging(handler);

// app/api/admin/users/[id]/role/route.ts
// PATCH /api/admin/users/:id/role — cambia el rol de un usuario
// Protegido: solo ADMIN (el rol se confirma contra la base en cada pedido)
// Body: { "role": "ADMIN" | "USER" }

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/db';
import { requireRole } from '@/lib/rbac';
import { parseJsonBody } from '@/lib/http';
import { Role } from '@prisma/client';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

const changeRoleSchema = z.object({
  role: z.nativeEnum(Role, {
    error: `El rol debe ser: ${Object.values(Role).join(' | ')}`,
  }),
});

type Context = { params: Promise<{ id: string }> };

async function handler(req: NextRequest, { params }: Context) {
  const authResult = await requireRole(req, [Role.ADMIN]);
  if (authResult instanceof NextResponse) return authResult; // 401 o 403

  const requestingUser = authResult;
  const { id } = await params;

  const parsed = await parseJsonBody(req, changeRoleSchema);
  if (!parsed.ok) return parsed.response;

  const { role: newRole } = parsed.data;

  // Un admin no puede quitarse el rol ADMIN a sí mismo
  if (id === requestingUser.userId && newRole !== Role.ADMIN) {
    return NextResponse.json(
      { error: 'Bad Request', message: 'No podés quitarte el rol ADMIN a vos mismo.' },
      { status: 400 }
    );
  }

  const targetUser = await prisma.user.findUnique({
    where: { id },
    select: { id: true, role: true },
  });

  if (!targetUser) {
    return NextResponse.json(
      { error: 'Not Found', message: 'Usuario no encontrado.' },
      { status: 404 }
    );
  }

  const updated = await prisma.user.update({
    where: { id },
    data: { role: newRole },
    select: { id: true, email: true, name: true, role: true, updatedAt: true },
  });

  log.info(`${requestingUser.userId} changed role of ${targetUser.id}: ${targetUser.role} → ${newRole}`);

  return NextResponse.json({
    message: 'Rol actualizado correctamente.',
    user: updated,
    changedBy: requestingUser.email,
  });
}

export const PATCH = withLogging<Context>(handler);

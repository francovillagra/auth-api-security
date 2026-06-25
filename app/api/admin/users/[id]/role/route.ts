// app/api/admin/users/[id]/role/route.ts
// PATCH /api/admin/users/:id/role — cambia el rol de un usuario
// Protegido: solo ADMIN
// Body: { "role": "ADMIN" | "USER" }

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/db';
import { requireRole } from '@/lib/rbac';
import { Role } from '@prisma/client';
import { log } from '@/lib/logger';

const changeRoleSchema = z.object({
  role: z.nativeEnum(Role, {
    error: `El rol debe ser: ${Object.values(Role).join(' | ')}`,
  }),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const authResult = requireRole(req, [Role.ADMIN]);
  if (authResult instanceof NextResponse) return authResult; // 401 o 403

  const requestingUser = authResult;
  const { id } = await params;

  const body = await req.json();
  const result = changeRoleSchema.safeParse(body);

  if (!result.success) {
    return NextResponse.json(
      { error: 'Validation failed', details: result.error.flatten().fieldErrors },
      { status: 400 }
    );
  }

  const { role: newRole } = result.data;

  // Un admin no puede quitarse el rol ADMIN a sí mismo
  if (id === requestingUser.userId && newRole !== Role.ADMIN) {
    return NextResponse.json(
      { error: 'Bad Request', message: 'No podés quitarte el rol ADMIN a vos mismo.' },
      { status: 400 }
    );
  }

  try {
    const targetUser = await prisma.user.findUnique({
      where: { id },
      select: { id: true, email: true, role: true },
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

    log.info(
      `${requestingUser.email} changed role of ${targetUser.email}: ${targetUser.role} → ${newRole}`
    );

    return NextResponse.json({
      message: 'Rol actualizado correctamente.',
      user: updated,
      changedBy: requestingUser.email,
    });
  } catch (error) {
    console.error('[admin/users/role] Error:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}

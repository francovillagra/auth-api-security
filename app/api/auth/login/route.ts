import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { verifyPassword, generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { loginSchema } from '@/lib/validations';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

async function handler(req: NextRequest) {
  const body = await req.json();
  const result = loginSchema.safeParse(body);

  if (!result.success) {
    return NextResponse.json(
      { error: 'Validation failed', details: result.error.flatten().fieldErrors },
      { status: 400 }
    );
  }

  const { email, password } = result.data;

  const user = await prisma.user.findUnique({ where: { email } });

  // Unified error message to prevent user enumeration
  if (!user || !(await verifyPassword(password, user.password))) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  // role incluido en el payload — necesario para que requireRole() funcione
  // sin tener que volver a consultar la DB en cada request protegido
  const payload = { userId: user.id, email: user.email, role: user.role };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  log.info(`User logged in: ${email}`);

  return NextResponse.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
    },
    accessToken,
    refreshToken,
  });
}

export const POST = withLogging(handler);

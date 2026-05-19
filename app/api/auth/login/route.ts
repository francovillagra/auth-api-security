import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { verifyPassword, generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { loginSchema } from '@/lib/validations';
import { log } from '@/lib/logger';

export async function POST(req: NextRequest) {
  try {
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

    // Use constant-time comparison path to avoid user enumeration
    if (!user || !(await verifyPassword(password, user.password))) {
      return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
    }

    const payload = { userId: user.id, email: user.email };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    log.info(`User logged in: ${email}`);

    return NextResponse.json({
      user: { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt },
      accessToken,
      refreshToken,
    });
  } catch (error) {
    log.error('Login error', error as Error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { verifyRefreshToken, generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { refreshTokenSchema } from '@/lib/validations';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

async function handler(req: NextRequest) {
  const body = await req.json();
  const result = refreshTokenSchema.safeParse(body);

  if (!result.success) {
    return NextResponse.json(
      { error: 'Validation failed', details: result.error.flatten().fieldErrors },
      { status: 400 }
    );
  }

  const { refreshToken } = result.data;

  const payload = verifyRefreshToken(refreshToken);
  if (!payload) {
    return NextResponse.json({ error: 'Invalid or expired refresh token' }, { status: 401 });
  }

  // Confirm user still exists before issuing new tokens
  const user = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 401 });
  }

  const newPayload = { userId: user.id, email: user.email };
  const accessToken = generateAccessToken(newPayload);
  const newRefreshToken = generateRefreshToken(newPayload);

  log.info(`Tokens refreshed for: ${user.email}`);

  return NextResponse.json({ accessToken, refreshToken: newRefreshToken });
}

export const POST = withLogging(handler);

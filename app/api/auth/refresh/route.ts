import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { verifyRefreshToken, generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { parseJsonBody } from '@/lib/http';
import { refreshTokenSchema } from '@/lib/validations';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

const INVALID = { error: 'Invalid or expired refresh token' };

async function handler(req: NextRequest) {
  const parsed = await parseJsonBody(req, refreshTokenSchema);
  if (!parsed.ok) return parsed.response;

  const payload = verifyRefreshToken(parsed.data.refreshToken);
  if (!payload) {
    return NextResponse.json(INVALID, { status: 401 });
  }

  // Confirm user still exists before issuing new tokens (y leer su rol actual)
  const user = await prisma.user.findUnique({ where: { id: payload.userId } });
  if (!user) {
    return NextResponse.json(INVALID, { status: 401 });
  }

  const newPayload = { userId: user.id, email: user.email, role: user.role };
  const accessToken = generateAccessToken(newPayload);
  const newRefreshToken = generateRefreshToken(newPayload);

  log.info(`Tokens refreshed for: ${user.id}`);

  return NextResponse.json({ accessToken, refreshToken: newRefreshToken });
}

export const POST = withLogging(handler);

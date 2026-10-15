import { NextRequest, NextResponse } from 'next/server';
import { generateAccessToken } from '@/lib/auth';
import { parseJsonBody } from '@/lib/http';
import { rotateRefreshToken } from '@/lib/refresh-tokens';
import { refreshTokenSchema } from '@/lib/validations';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

// Una sola respuesta para todo lo que no sea un refresh token vigente: firma inválida, desconocido,
// vencido, ya usado o usuario eliminado. Quien llama no aprende nada sobre por qué falló.
const INVALID = { error: 'Invalid or expired refresh token' };

async function handler(req: NextRequest) {
  const parsed = await parseJsonBody(req, refreshTokenSchema);
  if (!parsed.ok) return parsed.response;

  const rotated = await rotateRefreshToken(parsed.data.refreshToken);
  if (!rotated) {
    return NextResponse.json(INVALID, { status: 401 });
  }

  log.info(`Tokens refreshed for: ${rotated.user.userId}`);

  return NextResponse.json({ accessToken: generateAccessToken(rotated.user), refreshToken: rotated.refreshToken });
}

export const POST = withLogging(handler);

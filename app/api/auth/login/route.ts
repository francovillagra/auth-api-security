import { NextRequest, NextResponse } from 'next/server';
import { verifyPasswordConstantTime, generateAccessToken } from '@/lib/auth';
import { startSession } from '@/lib/refresh-tokens';
import { parseJsonBody } from '@/lib/http';
import { loginSchema } from '@/lib/validations';
import { findUserByEmail } from '@/lib/users';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

async function handler(req: NextRequest) {
  const parsed = await parseJsonBody(req, loginSchema);
  if (!parsed.ok) return parsed.response;

  const { email, password } = parsed.data;

  const user = await findUserByEmail(email);

  // Se compara SIEMPRE contra un hash (el del usuario o uno falso) para que el tiempo de
  // respuesta no delate si el email existe, y se devuelve el mismo mensaje en ambos casos.
  const passwordMatches = await verifyPasswordConstantTime(password, user?.password);
  if (!user || !passwordMatches) {
    return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
  }

  // role incluido en el payload solo como dato informativo para el cliente: las rutas
  // protegidas por rol vuelven a leerlo de la base (ver lib/rbac.ts).
  const payload = { userId: user.id, email: user.email, role: user.role };
  const accessToken = generateAccessToken(payload);
  const refreshToken = await startSession(payload);

  log.info(`User logged in: ${user.id}`);

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

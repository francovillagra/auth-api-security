import { NextRequest, NextResponse } from 'next/server';
import { parseJsonBody } from '@/lib/http';
import { revokeSession } from '@/lib/refresh-tokens';
import { logoutSchema } from '@/lib/validations';
import { withLogging } from '@/lib/request-logger';

/**
 * Cierra la sesión del refresh token recibido (o todas con `everywhere: true`). Es idempotente y
 * responde 204 aunque el token sea inválido, vencido o ya revocado: para quien llama el resultado es
 * el mismo (esa sesión ya no sirve) y la respuesta no confirma si un token era válido.
 */
async function handler(req: NextRequest) {
  const parsed = await parseJsonBody(req, logoutSchema);
  if (!parsed.ok) return parsed.response;

  await revokeSession(parsed.data.refreshToken, { everywhere: parsed.data.everywhere });
  return new NextResponse(null, { status: 204 });
}

export const POST = withLogging(handler);

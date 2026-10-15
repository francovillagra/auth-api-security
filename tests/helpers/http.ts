import { NextRequest } from 'next/server';

/** Arma un NextRequest JSON como lo recibiría un route handler. */
export function jsonRequest(
  path: string,
  { method = 'POST', body, headers = {} }: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
): NextRequest {
  const raw = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
  return new NextRequest(`http://localhost${path}`, {
    method,
    headers: { ...(raw === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    body: raw,
  });
}

export function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** Cuerpo JSON de una respuesta, sin tipar (los tests afirman sobre los campos que les interesan). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function readJson(response: Response): Promise<any> {
  return response.json();
}

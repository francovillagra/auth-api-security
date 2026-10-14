import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

/** Ningún endpoint necesita más que unos pocos campos de texto. */
export const MAX_JSON_BYTES = 8 * 1024;

export function errorResponse(error: string, status: number, extra: Record<string, unknown> = {}) {
  return NextResponse.json({ error, ...extra }, { status });
}

type Parsed<S extends z.ZodType> = { ok: true; data: z.output<S> } | { ok: false; response: NextResponse };

/** Lee el cuerpo de a trozos y corta apenas supera el máximo; devuelve `null` si era demasiado grande. */
async function readLimited(req: NextRequest, maxBytes: number): Promise<string | null> {
  const reader = req.body?.getReader();
  if (!reader) return '';

  const decoder = new TextDecoder();
  let text = '';
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/**
 * Lee y valida el cuerpo JSON de un pedido. Devuelve la respuesta de error lista para enviar:
 *  - 415 si el Content-Type no es application/json
 *  - 413 si el cuerpo supera `maxBytes`
 *  - 400 si el JSON está roto o no cumple el esquema
 */
export async function parseJsonBody<S extends z.ZodType>(
  req: NextRequest,
  schema: S,
  maxBytes: number = MAX_JSON_BYTES,
): Promise<Parsed<S>> {
  if (!/^application\/json\s*(;|$)/i.test(req.headers.get('content-type') ?? '')) {
    return { ok: false, response: errorResponse('Content-Type must be application/json', 415) };
  }

  const declared = Number(req.headers.get('content-length') ?? 0);
  if (declared > maxBytes) return { ok: false, response: errorResponse('Request body too large', 413) };

  const raw = await readLimited(req, maxBytes);
  if (raw === null) return { ok: false, response: errorResponse('Request body too large', 413) };

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    return { ok: false, response: errorResponse('Invalid JSON', 400) };
  }

  const result = schema.safeParse(json);
  if (!result.success) {
    return {
      ok: false,
      response: errorResponse('Validation failed', 400, { details: z.flattenError(result.error).fieldErrors }),
    };
  }
  return { ok: true, data: result.data };
}

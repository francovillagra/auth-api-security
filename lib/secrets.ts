/**
 * Validación de los secretos con que se firman los JWT.
 *
 * La API falla al arrancar (cerrada) si un secreto falta, es corto, parece un valor de
 * ejemplo o se repite entre access y refresh. Nunca incluye el valor del secreto en el
 * mensaje de error.
 */

export const MIN_SECRET_LENGTH = 32;

const HOW_TO = 'Generá uno con: openssl rand -base64 48';

/** Valores de ejemplo típicos de .env.example / documentación. */
const PLACEHOLDER = /change[-_ ]?(this|me)|reemplazar|replace[-_ ]?me|your[-_ ]?secret|placeholder|example|secreto-seguro|openssl/i;

export function validateSecret(name: string, value: string | undefined): string {
  if (!value || value.trim() === '') {
    throw new Error(`${name} no está definido. ${HOW_TO}`);
  }
  if (value.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} es demasiado corto (mínimo ${MIN_SECRET_LENGTH} caracteres). ${HOW_TO}`);
  }
  if (PLACEHOLDER.test(value)) {
    throw new Error(`${name} parece un valor de ejemplo, no un secreto real. ${HOW_TO}`);
  }
  if (new Set(value).size < 10) {
    throw new Error(`${name} tiene muy poca variedad de caracteres. ${HOW_TO}`);
  }
  return value;
}

export interface JwtSecrets {
  access: string;
  refresh: string;
}

export function loadJwtSecrets(env: Record<string, string | undefined> = process.env): JwtSecrets {
  const access = validateSecret('JWT_SECRET', env.JWT_SECRET);
  const refresh = validateSecret('JWT_REFRESH_SECRET', env.JWT_REFRESH_SECRET);
  if (access === refresh) {
    throw new Error('JWT_SECRET y JWT_REFRESH_SECRET deben ser distintos entre sí.');
  }
  return { access, refresh };
}

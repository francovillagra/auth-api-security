// Lo que comparten setup.mjs y launch.mjs: leer las credenciales del volumen y armar el entorno con que corre la API.
//
// Los secretos se leen del volumen `demo_state` (lo llena init.py la primera vez) y se pasan solo como variables de entorno de los
// procesos que los necesitan. No hay ninguno en el repositorio ni en la imagen.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const STATE_DIR = process.env.DEMO_STATE_DIR ?? '/run/demo';

// Los mismos nombres que usa el servicio `postgres` del docker-compose.yml (hay una prueba que comprueba que coinciden).
const DB_USER = process.env.DEMO_DB_USER ?? 'authapi';
const DB_NAME = process.env.DEMO_DB_NAME ?? 'authapi';
const DB_HOST = process.env.DEMO_DB_HOST ?? 'postgres';

export function readState(name) {
  return readFileSync(join(STATE_DIR, name), 'utf8').trim();
}

/** Variables de entorno de la API de la demo. */
export function apiEnv(base = process.env) {
  const dbPassword = readState('postgres_password');
  return {
    ...base,
    NODE_ENV: 'production',
    JWT_SECRET: readState('jwt_secret'),
    JWT_REFRESH_SECRET: readState('jwt_refresh_secret'),
    DATABASE_URL: `postgresql://${DB_USER}:${encodeURIComponent(dbPassword)}@${DB_HOST}:5432/${DB_NAME}?schema=public`,
    // Sin CORS (solo mismo origen): la consola habla con la API de servidor a servidor, no desde el navegador.
    CORS_ORIGIN: '',
    // Sin Upstash: la API limita el ritmo en memoria, y la red de la demo no tiene salida a internet.
    UPSTASH_REDIS_REST_URL: '',
    UPSTASH_REDIS_REST_TOKEN: '',
    NEXT_TELEMETRY_DISABLED: '1',
  };
}

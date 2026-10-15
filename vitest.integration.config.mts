import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// Pruebas de integración: route handlers reales + Prisma real + PostgreSQL real.
// Necesitan TEST_DATABASE_URL apuntando a una base DESCARTABLE con las migraciones aplicadas
// (cada test la vacía). Ver "Testing" en el README.
export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('./', import.meta.url)) } },
  test: {
    environment: 'node',
    include: ['tests/integration/**/*.test.ts'],
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    env: {
      DATABASE_URL: process.env.TEST_DATABASE_URL ?? '',
      JWT_SECRET: 'test-access-secret-0123456789-abcdefghijklmnop',
      JWT_REFRESH_SECRET: 'test-refresh-secret-0123456789-abcdefghijklmno',
      NODE_ENV: 'test',
    },
  },
});

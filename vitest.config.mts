import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: { alias: { '@': fileURLToPath(new URL('./', import.meta.url)) } },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Las pruebas de integración necesitan PostgreSQL: se corren aparte (npm run test:integration).
    exclude: ['tests/integration/**', 'node_modules/**'],
    setupFiles: ['tests/helpers/setup.ts'],
    // lib/auth.ts valida los secretos al importarse: se definen antes de cargar cualquier módulo.
    env: {
      JWT_SECRET: 'test-access-secret-0123456789-abcdefghijklmnop',
      JWT_REFRESH_SECRET: 'test-refresh-secret-0123456789-abcdefghijklmno',
      NODE_ENV: 'test',
    },
  },
});

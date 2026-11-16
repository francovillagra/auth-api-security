// Prepara la base de práctica: aplica las migraciones del proyecto y carga los datos de práctica.
// Corre una vez por encendido, después de que la base responde y antes de que arranque la API. Se puede repetir sin efectos de más.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import prismaPackage from '@prisma/client';
import bcrypt from 'bcryptjs';
import { apiEnv, readState, STATE_DIR } from './env.mjs';
import { seedUsers } from './seed.mjs';

const env = apiEnv();

console.log('Base de práctica: aplicando las migraciones…');
// El mismo comando que usa la guía de despliegue del README (`npx prisma migrate deploy`), sin pasar por npx.
const migrate = spawnSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], { env, stdio: 'inherit' });
if (migrate.status !== 0) {
  console.error('No se pudieron aplicar las migraciones (ver arriba).');
  process.exit(migrate.status ?? 1);
}

const { PrismaClient } = prismaPackage;
const prisma = new PrismaClient({ datasources: { db: { url: env.DATABASE_URL } } });
try {
  const seed = JSON.parse(readFileSync(join(STATE_DIR, 'seed.json'), 'utf8'));
  await seedUsers(prisma, { seed, adminPassword: readState('admin_password'), hash: (password) => bcrypt.hash(password, 10) });
  console.log(`Datos de práctica cargados: administración y ${seed.customers.length} clientes.`);
} finally {
  await prisma.$disconnect();
}

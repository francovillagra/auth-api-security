// Pruebas de los scripts de Node de la demo (env, seed y launch). No necesitan Docker, ni base de datos, ni Next:
//   node --test "demo/tests/*.test.mjs"
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const DEMO = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function stateDir(extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'demo-state-'));
  const files = {
    postgres_password: 'pg pass/with:odd?chars\n',
    jwt_secret: 'secreto-de-prueba-uno-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n',
    jwt_refresh_secret: 'secreto-de-prueba-dos-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n',
    admin_password: 'clave-admin-de-prueba\n',
    ...extra,
  };
  for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
  return dir;
}

// -- env.mjs --------------------------------------------------------------------------------------------------------------

test('apiEnv lee los secretos del volumen y arma el entorno de la API', async () => {
  process.env.DEMO_STATE_DIR = stateDir();
  const { apiEnv } = await import(`${DEMO}/env.mjs?case=1`);
  const env = apiEnv({ PATH: '/usr/bin' });
  assert.equal(env.NODE_ENV, 'production');
  assert.equal(env.JWT_SECRET, 'secreto-de-prueba-uno-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  assert.equal(env.JWT_REFRESH_SECRET, 'secreto-de-prueba-dos-bbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
  assert.notEqual(env.JWT_SECRET, env.JWT_REFRESH_SECRET);
  // La contraseña de la base va codificada: un carácter raro no puede romper la dirección.
  const url = new URL(env.DATABASE_URL);
  assert.equal(decodeURIComponent(url.password), 'pg pass/with:odd?chars');
  assert.equal(url.username, 'authapi');
  assert.equal(url.hostname, 'postgres');
  assert.equal(url.pathname, '/authapi');
  assert.equal(env.PATH, '/usr/bin');
});

test('apiEnv: sin CORS ni Upstash (la demo no tiene salida a internet)', async () => {
  process.env.DEMO_STATE_DIR = stateDir();
  const { apiEnv } = await import(`${DEMO}/env.mjs?case=2`);
  const env = apiEnv({});
  assert.equal(env.CORS_ORIGIN, '');
  assert.equal(env.UPSTASH_REDIS_REST_URL, '');
  assert.equal(env.UPSTASH_REDIS_REST_TOKEN, '');
});

test('readState: un archivo que falta es un error; uno vacío da texto vacío (la API se niega a arrancar con eso)', async () => {
  const dir = stateDir();
  writeFileSync(join(dir, 'jwt_secret'), '');
  process.env.DEMO_STATE_DIR = dir;
  const { readState } = await import(`${DEMO}/env.mjs?case=3`);
  assert.equal(readState('jwt_secret'), '');
  assert.throws(() => readState('no_existe'), /ENOENT/);
});

// -- seed.mjs -------------------------------------------------------------------------------------------------------------

function fakePrisma() {
  const rows = new Map();
  return {
    rows,
    user: {
      async upsert({ where, update, create }) {
        const current = rows.get(where.email);
        if (current) Object.assign(current, update);
        else rows.set(where.email, { ...create });
        return rows.get(where.email);
      },
    },
  };
}

const SEED = {
  admin: { email: 'admin@tienda-demo.test', name: 'Administración (práctica)' },
  customers: [
    { email: 'ana@tienda-demo.test', name: 'Ana Demo' },
    { email: 'luis@tienda-demo.test', name: 'Luis Demo' },
  ],
};
const fakeHash = async (password) => `hash(${password})`;

test('seedUsers carga la administración con su contraseña y los clientes con claves al azar', async () => {
  const { seedUsers } = await import(`${DEMO}/seed.mjs`);
  const prisma = fakePrisma();
  const generated = [];
  await seedUsers(prisma, {
    seed: SEED,
    adminPassword: 'clave-admin',
    hash: fakeHash,
    makePassword: () => {
      generated.push(`azar-${generated.length}`);
      return generated.at(-1);
    },
  });
  assert.equal(prisma.rows.size, 3);
  const admin = prisma.rows.get('admin@tienda-demo.test');
  assert.equal(admin.role, 'ADMIN');
  assert.equal(admin.password, 'hash(clave-admin)');
  for (const email of ['ana@tienda-demo.test', 'luis@tienda-demo.test']) {
    assert.equal(prisma.rows.get(email).role, 'USER');
  }
  // Cada cliente tiene su propia contraseña y en la base queda solo el hash.
  assert.deepEqual(generated, ['azar-0', 'azar-1']);
  assert.equal(prisma.rows.get('ana@tienda-demo.test').password, 'hash(azar-0)');
  assert.equal(prisma.rows.get('luis@tienda-demo.test').password, 'hash(azar-1)');
});

test('seedUsers se puede repetir: repone la administración y no toca a los clientes', async () => {
  const { seedUsers } = await import(`${DEMO}/seed.mjs`);
  const prisma = fakePrisma();
  await seedUsers(prisma, { seed: SEED, adminPassword: 'primera', hash: fakeHash });
  const customerBefore = { ...prisma.rows.get('ana@tienda-demo.test') };
  prisma.rows.get('admin@tienda-demo.test').role = 'USER'; // alguien le quitó el permiso
  await seedUsers(prisma, { seed: SEED, adminPassword: 'segunda', hash: fakeHash });
  assert.equal(prisma.rows.size, 3);
  assert.equal(prisma.rows.get('admin@tienda-demo.test').role, 'ADMIN');
  assert.equal(prisma.rows.get('admin@tienda-demo.test').password, 'hash(segunda)');
  assert.deepEqual(prisma.rows.get('ana@tienda-demo.test'), customerBefore);
});

test('las contraseñas al azar por defecto son largas y distintas', async () => {
  const { seedUsers } = await import(`${DEMO}/seed.mjs`);
  const prisma = fakePrisma();
  const seen = [];
  await seedUsers(prisma, {
    seed: SEED,
    adminPassword: 'x',
    hash: async (password) => {
      seen.push(password);
      return 'h';
    },
  });
  const [, first, second] = seen;
  assert.ok(first.length >= 20 && second.length >= 20);
  assert.notEqual(first, second);
});

// -- launch.mjs -----------------------------------------------------------------------------------------------------------

/** Una carpeta de trabajo con un `next` de mentira (imprime lo que recibió) para probar el arranque sin Next. */
function fakeNextProject(script) {
  const cwd = mkdtempSync(join(tmpdir(), 'demo-launch-'));
  const bin = join(cwd, 'node_modules', 'next', 'dist', 'bin');
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'next'), script);
  chmodSync(join(bin, 'next'), 0o755);
  return cwd;
}

function runLaunch(cwd, { state = stateDir(), shared = mkdtempSync(join(tmpdir(), 'demo-shared-')), env = {} } = {}) {
  const child = spawn(process.execPath, [join(DEMO, 'launch.mjs')], {
    cwd,
    env: { PATH: process.env.PATH, DEMO_STATE_DIR: state, DEMO_SHARED_DIR: shared, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  const waiting = [];
  const onData = (chunk) => {
    out += chunk;
    for (const waiter of [...waiting]) {
      if (waiter.pattern.test(out)) {
        waiting.splice(waiting.indexOf(waiter), 1);
        waiter.resolve();
      }
    }
  };
  child.stdout.on('data', onData);
  child.stderr.on('data', onData);
  const done = new Promise((resolveDone) => child.on('exit', (code, signal) => resolveDone({ code, signal, out })));
  const waitFor = (pattern) => new Promise((resolveWait) => (pattern.test(out) ? resolveWait() : waiting.push({ pattern, resolve: resolveWait })));
  return { child, done, shared, waitFor };
}

test('launch arranca next start con las credenciales, escucha en 0.0.0.0 y copia el registro', async () => {
  const cwd = fakeNextProject(
    [
      'console.log("argumentos:", process.argv.slice(2).join(" "));',
      'console.log("hay JWT_SECRET:", Boolean(process.env.JWT_SECRET), "| NODE_ENV:", process.env.NODE_ENV, "| HOSTNAME:", process.env.HOSTNAME);',
      'console.error("2026-01-01 10:00:00 [warn]: una advertencia");',
    ].join('\n'),
  );
  const { done, shared } = runLaunch(cwd);
  const { code, out } = await done;
  assert.equal(code, 0);
  assert.match(out, /argumentos: start --hostname 0\.0\.0\.0 --port 3000/);
  assert.match(out, /hay JWT_SECRET: true \| NODE_ENV: production \| HOSTNAME: 0\.0\.0\.0/);
  // El registro sale por la salida normal y además queda copiado para la consola.
  const copy = readFileSync(join(shared, 'api.log'), 'utf8');
  assert.match(copy, /argumentos: start --hostname 0\.0\.0\.0 --port 3000/);
  assert.match(copy, /\[warn\]: una advertencia/);
  assert.ok(!copy.includes('secreto-de-prueba'), 'el registro no tiene que traer secretos');
});

test('launch: el código de salida de la API es el del contenedor', async () => {
  const cwd = fakeNextProject('process.exit(7);');
  const { code } = await runLaunch(cwd).done;
  assert.equal(code, 7);
});

test('launch: si no se puede escribir la copia del registro, la API sigue', async () => {
  const cwd = fakeNextProject('console.log("sigue viva");');
  const { code, out } = await runLaunch(cwd, { shared: '/no/existe/esta/carpeta' }).done;
  assert.equal(code, 0);
  assert.match(out, /sigue viva/);
});

test('launch: SIGTERM llega a la API (docker stop la cierra bien)', async () => {
  const cwd = fakeNextProject(
    [
      'process.on("SIGTERM", () => { console.log("recibí SIGTERM"); process.exit(0); });',
      'console.log("lista");',
      'setInterval(() => {}, 1000);',
    ].join('\n'),
  );
  const { child, done, waitFor } = runLaunch(cwd);
  await waitFor(/lista/);
  child.kill('SIGTERM');
  const { code, out } = await done;
  assert.equal(code, 0);
  assert.match(out, /recibí SIGTERM/);
});

test('launch: la copia del registro no crece sin límite', async () => {
  const cwd = fakeNextProject(
    ['const linea = "x".repeat(1000) + "\\n";', 'for (let i = 0; i < 2600; i++) console.log(linea.trim());'].join('\n'),
  );
  const { shared, done } = runLaunch(cwd);
  await done;
  const size = readFileSync(join(shared, 'api.log')).length;
  assert.ok(size < 2.2 * 1024 * 1024, `la copia pesa ${size} bytes`);
});

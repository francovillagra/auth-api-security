// Arranca la API real (`next start`) con las credenciales de la demo y deja una copia de su registro en la carpeta compartida,
// para que la consola pueda mostrar lo que el servidor registra mientras se hacen las pruebas.
//
// El registro sigue saliendo también por la salida normal del contenedor (`docker compose logs api`). La copia es un extra: si no se
// puede escribir, la API sigue funcionando igual. Se acota en tamaño (la demo es de uso corto).
import { spawn } from 'node:child_process';
import { appendFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { apiEnv } from './env.mjs';

const SHARED_DIR = process.env.DEMO_SHARED_DIR ?? '/run/shared';
const LOG_FILE = join(SHARED_DIR, 'api.log');
const MAX_LOG_BYTES = 2 * 1024 * 1024;
const PORT = process.env.PORT ?? '3000';

function copyToLog(chunk) {
  try {
    let size = 0;
    try {
      size = statSync(LOG_FILE).size;
    } catch {
      // todavía no existe
    }
    if (size > MAX_LOG_BYTES) writeFileSync(LOG_FILE, '');
    appendFileSync(LOG_FILE, chunk);
  } catch {
    // el registro compartido es un extra
  }
}

const child = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '--hostname', '0.0.0.0', '--port', PORT], {
  // HOSTNAME: Docker lo fija al id del contenedor; acá se pisa para que nada lo tome como dirección de escucha.
  env: { ...apiEnv(), HOSTNAME: '0.0.0.0', PORT },
  stdio: ['ignore', 'pipe', 'pipe'],
});

child.stdout.on('data', (chunk) => {
  process.stdout.write(chunk);
  copyToLog(chunk);
});
child.stderr.on('data', (chunk) => {
  process.stderr.write(chunk);
  copyToLog(chunk);
});

// docker stop manda SIGTERM al proceso 1: se lo pasa a la API para que cierre bien.
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => child.kill(signal));
}
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));

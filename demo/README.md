# Demo local de Auth API Security

La **API real del proyecto** (Next.js, Prisma y PostgreSQL), una base de datos de práctica y una **consola guiada** con botones, todo en esta computadora y con un solo comando. Sirve para ver cómo responde una API de inicio de sesión: primero se usa como lo haría un cliente de una tienda y después se la ataca con técnicas reales, sin tocar ningún sistema ajeno.

```
Consola guiada ──▶ API de Auth API Security ──▶ PostgreSQL de práctica
 localhost:4200      next start (la del repositorio)   (en memoria, con cuentas de práctica)
                          │
                          └──▶ su registro (logs) ──▶ la consola lo muestra en pantalla
```

La API, la base y la consola viven en una red de Docker **sin salida**: no pueden hablar con internet ni con la red local. Lo que muestra la consola es lo que la API contestó de verdad, no una animación: cada veredicto se calcula a partir de sus respuestas.

## Qué se necesita

- **Docker Desktop** (Windows con WSL2, macOS o Linux) o Docker Engine con Compose v2. Comprobar con `docker compose version`.
- Unos 3 GB libres y conexión a internet **solo para construir** la primera vez (imágenes y paquetes). Después funciona sin internet.

## Arrancar

Desde una terminal (PowerShell, cmd, bash), en la carpeta `demo/` del repositorio:

```bash
cd demo
docker compose up --build
```

La primera vez tarda varios minutos porque construye la API (`next build`). Cuando aparece `Consola de la demo lista`, abrir **http://localhost:4200**. Arriba dice **Sistema listo** cuando la API ya responde.

Para dejarlo en segundo plano, esperando a que todo esté sano, y apagarlo después:

```bash
docker compose up -d --build --wait
docker compose down
```

## Cómo usarla

La página tiene tres partes. Cada acción deja constancia en **Lo que va pasando**, y **Lo que registra la API** muestra el registro real del servidor.

### Parte 1. Usarla como un cliente

| Paso | Qué ocurre |
|---|---|
| **Crear la cuenta de práctica** | La API crea la cuenta de un cliente y le entrega dos llaves: una de acceso (vale 15 minutos) y una de renovación (vale 7 días y se usa una sola vez). |
| **Pedir mi perfil** / **Probar sin llave** | Con la llave de acceso la API devuelve los datos del cliente; sin llave responde `401`. |
| **Renovar la sesión** / **Cerrar sesión** / **Entrar de nuevo** | Cada renovación cambia la llave de renovación por una nueva y la anterior deja de servir. |
| **Ver las cuentas como administración** | Solo la cuenta con rol de administración ve el listado, y nunca incluye contraseñas. |

### Parte 2. Atacarla

Cada botón **Probar este ataque** lanza el ataque contra la API de práctica y muestra, intento por intento, qué contestó. Se puede repetir las veces que haga falta: cada vez usa un origen distinto. Se corre un ataque a la vez.

| Ataque | Qué simula | Qué debe contestar la API |
|---|---|---|
| Adivinar una contraseña a los golpes | 8 contraseñas comunes, una tras otra, contra una cuenta de práctica | `401` los primeros 5 intentos y `429` (con `Retry-After`) desde el sexto |
| Robar una sesión y usarla después | Alguien copia la llave de renovación de un cliente y la usa cuando el dueño ya renovó | `401` a la llave copiada; la sesión entera se cierra (también para el dueño, que vuelve a entrar con su contraseña) y el registro dice `Refresh token reuse detected` |
| Fabricar una llave de administrador | 5 llaves falsas: ninguna, sin firma (`alg: none`), con claves adivinadas y una verdadera con el rol editado | `401` las cinco |
| Un cliente intenta entrar al panel de administración | Un cliente pide el listado de cuentas y se da a sí mismo el rol de administración | `403` las dos veces; sigue siendo cliente; la administración sí ve el listado, sin contraseñas |
| Cambiar el rol de una persona en pleno uso | Se da y se quita el cargo de administración a un empleado con la sesión abierta | `403`, luego `200` y luego `403` otra vez con la misma llave: el rol se lee de la base en cada pedido |
| Mandar datos mal armados o enormes | Un correo con forma de ataque a la base, un texto roto, un envío de 20 KB y un formato inesperado | `400`, `400`, `413` y `415` |

### Parte 3. Lo que todavía no cubre

Una revisión de seguridad también dice lo que falta. Estos dos puntos figuran en «Limitaciones conocidas» del README del proyecto y se pueden reproducir acá. La demo los muestra con el mismo detalle que los ataques que la API frena; los veredictos de esta parte son **«límite conocido»**.

| Límite | Qué muestra | Qué contesta hoy la API |
|---|---|---|
| Cambiar de dirección para esquivar el freno | 8 intentos contra la misma cuenta, cada uno declarando una dirección distinta | `401` los ocho: el freno cuenta por dirección y no por cuenta |
| Seguir usando la llave de acceso después de cerrar sesión | Un cliente cierra sesión y alguien que había copiado su llave de acceso la usa | `204`, `401` a la renovación y `200` a la llave de acceso, que vale hasta que vence |

Si el proyecto corrige alguno de estos límites, la prueba de humo (más abajo) lo avisa y hay que actualizar la demo y este README.

## Direcciones y puertos

| Qué | Dirección | Variable para cambiar el puerto |
|---|---|---|
| Consola guiada | http://localhost:4200 | `DEMO_CONSOLE_PORT` |

La API y la base **no publican ningún puerto**: solo se llega a ellas a través de la consola. Si el puerto está ocupado, elegir otro:

```powershell
# PowerShell
$env:DEMO_CONSOLE_PORT = 4300
docker compose up --build
```

```bash
# bash / zsh
DEMO_CONSOLE_PORT=4300 docker compose up --build
```

## Apagar, reiniciar y empezar de cero

| Comando | Efecto |
|---|---|
| `Ctrl + C` (en primer plano) o `docker compose down` | Apaga todo. La base vive en memoria: la próxima vez empieza vacía y se vuelve a cargar con las cuentas de práctica. |
| `docker compose down -v` | Además borra las credenciales generadas; la próxima vez se crean otras. |
| `docker compose up` (sin `--build`) | Vuelve a encender sin reconstruir. |
| Botón **Reiniciar el recorrido** (pie de la página; pide confirmar con un segundo clic) | Deja la página como al principio (cliente, resultados y registro en pantalla) sin apagar nada. Las cuentas de práctica que se crearon siguen en la base hasta apagar. |

El freno de intentos de la API es de 5 pedidos cada 10 segundos por dirección. Si un ataque avisa que la API está limitando los pedidos, basta esperar unos segundos y repetirlo.

## Prueba de aceptación en Docker Desktop

Lo que sigue confirma que la demo anda en una computadora real. Lleva unos 15 minutos la primera vez.

1. **Encender.** `cd demo` y `docker compose up --build`. Esperar `Consola de la demo lista` y abrir http://localhost:4200: arriba debe decir **Sistema listo**.
2. **Estado de los servicios.** En otra terminal, `docker compose ps -a`: `init` y `setup` terminan con código 0 (`Exited (0)`) y `postgres`, `api` y `console` figuran como `healthy`.
3. **Prueba de humo automática.** Desde cualquier carpeta del repositorio:

   ```bash
   python demo/tests/smoke.py          # en Windows también sirve:  python demo\tests\smoke.py   (o py demo\tests\smoke.py)
   ```

   Necesita solo Python 3.8 o más nuevo (sin instalar nada). Recorre los 17 pasos de la demo contra la API verdadera y debe terminar con `Todo salió como se esperaba (17 pasos...)`. Si el puerto no es el 4200, agregar `--port 4300`. Si falla, dice en qué paso y qué esperaba.

   **Aviso:** la prueba crea cuentas de práctica en la base de la demo y reinicia el recorrido al empezar y al terminar. Está pensada para que la corra el dueño de la demo, en su computadora. Si se corre dos veces seguidas, la segunda espera unos segundos, y lo avisa en pantalla, a que la API deje de frenar al cliente del recorrido.
4. **Recorrido a mano.** En el navegador, seguir las tres partes de la página. Los seis ataques de la Parte 2 deben terminar en **«La API lo frenó»** y los dos de la Parte 3 en **«Límite conocido»**.
5. **Comprobaciones de seguridad.**
   - La API no tiene salida a internet: este comando **debe terminar con un error** (no con una página):

     ```bash
     docker compose exec api node -e "require('http').get('http://example.com', {timeout: 5000}, (r) => { console.log(r.statusCode); process.exit(0); }).on('error', (e) => { console.error(e.code); process.exit(1); })"
     ```
   - Solo la consola publica un puerto: en `docker compose ps`, únicamente la consola figura con una flecha, `127.0.0.1:4200->8080/tcp`.
   - Los contenedores propios corren sin root: `docker compose exec console id -u` debe imprimir `10002` y `docker compose exec api id -u`, `1000`.
6. **Apagar.** `docker compose down` (o `docker compose down -v` para empezar de cero).

Si algo de esto no da lo esperado, pasar la salida de `docker compose ps -a` y de `docker compose logs --tail 80 setup api console`.

## Qué es de verdad y qué es de práctica

- **De verdad:** el código de la API (se construye con `next build` y se ejecuta con `next start`, sin cambios), las migraciones de Prisma, PostgreSQL 16, los tokens firmados, el límite de pedidos, la validación, los roles y el registro. Los ataques son pedidos HTTP reales contra esa API.
- **De práctica:** las cuentas (la administración y tres clientes, con correos `.test`), las contraseñas (generadas al azar la primera vez), la tienda («Tienda Demo») y las direcciones de origen.
- **Las direcciones de origen.** La API limita el ritmo de los pedidos por dirección de internet. Para que cada personaje (el cliente, la administración, cada atacante) tenga su propio contador, la consola declara una dirección distinta con la cabecera `x-real-ip`, que es justo la que la API lee cuando está en Vercel. Todas pertenecen a los bloques que el estándar RFC 5737 reserva para documentación (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`): no son de nadie. Es también lo que muestra el límite «Cambiar de dirección para esquivar el freno».

## Seguridad de la demo

- **Solo local y sin salida.** La red `lab` es `internal: true`: la API y la base no pueden hablar con internet ni con la red local, y los ataques de la consola solo pueden llegar a la API de práctica. Solo la consola se publica, y solo en `127.0.0.1`: nadie de la red local puede entrar.
- **Sin credenciales en el repositorio.** La primera vez, el servicio `init` (`init.py`) genera al azar la contraseña de la base, los dos secretos con que la API firma sus llaves y la contraseña de la cuenta de administración de práctica, y los guarda en un volumen de Docker. No se imprimen. La API se niega a arrancar con secretos débiles, y estos cumplen sus mismas reglas.
- **La API no se modifica.** La imagen se construye con el código del repositorio tal cual está; solo cambian las variables de entorno y un arranque que copia el registro a una carpeta compartida de solo lectura para la consola.
- **La consola no ataca nada ajeno.** Solo le habla a la dirección de la API de la demo, que recibe por configuración, y la página no puede indicarle otra. Acepta pedidos únicamente de su propia página (controla `Host` contra rebinding de DNS y `Origin` para que otro sitio abierto en el navegador no pueda dispararla), limita el tamaño de los pedidos, usa una política de contenido estricta (sin código en línea) y escribe en pantalla solo como texto.
- **Las llaves no llegan a la página.** Las llaves de acceso y de renovación del cliente de práctica quedan en el servidor de la consola; la página recibe solo datos ya preparados (correo, rol, vencimiento).
- **Contenedores acotados.** La API, `setup` y la consola corren sin root, con el sistema de archivos de solo lectura, sin privilegios extra y sin capacidades de Linux. `init` (sin red, termina enseguida) es el único que corre como root, solo para dejar los archivos a nombre del usuario correcto, y con tres capacidades de Linux (`CHOWN`, `DAC_OVERRIDE` y `FOWNER`). PostgreSQL es la imagen oficial con su configuración habitual, sin puertos publicados, y su base vive en memoria.
- Esto es una demo en una computadora personal: no está pensada para exponerse en una red ni en internet. **Los ataques de la consola solo son aceptables contra esta API de práctica; no deben apuntarse a sistemas ajenos.**

## Problemas frecuentes

| Síntoma | Qué hacer |
|---|---|
| `Cannot connect to the Docker daemon` | Abrir Docker Desktop y esperar a que indique que el motor de Docker está en ejecución. |
| El puerto 4200 está ocupado | Elegir otro con `DEMO_CONSOLE_PORT` (ver arriba) y encender de nuevo. |
| La consola sigue en «Esperando que la API termine de arrancar…» pasado un minuto | `docker compose ps -a` y `docker compose logs --tail 80 setup api postgres`. |
| Un ataque avisa que la API está limitando los pedidos | Es el freno de 5 pedidos cada 10 segundos funcionando. Esperar unos segundos y repetir. |
| «La sesión de la cuenta de práctica ya no existe» | Se reinició la base (vive en memoria). Crear la cuenta otra vez, paso 1. |
| Quedaron credenciales viejas después de reconstruir | `docker compose down -v` y volver a encender. |
| La primera construcción es lenta | Es normal (`next build`, descarga de imágenes y paquetes). Las siguientes usan la caché. |
| La computadora usa un proxy | La demo lo ignora a propósito (la red de la demo no sale a ningún lado). Solo la construcción necesita internet. |

## Cómo está armado

```
demo/
├── docker-compose.yml        # init, postgres, setup, api y console
├── api.Dockerfile            # construye la API del repositorio (next build) y la deja lista para next start
├── tools.Dockerfile          # imagen de la consola y de init (Python, sin dependencias)
├── init.py / common.py       # genera credenciales y datos de práctica la primera vez
├── setup.mjs / seed.mjs      # crea las tablas (prisma migrate deploy) y carga las cuentas de práctica
├── env.mjs / launch.mjs      # arma el entorno de la API desde los secretos y copia su registro a la carpeta compartida
├── console/
│   ├── server.py             # la consola (solo biblioteca estándar de Python)
│   ├── scenarios.py          # los ataques: cada veredicto sale de las respuestas de la API
│   ├── api.py                # el cliente de la API, los orígenes de práctica y las llaves de prueba
│   ├── serverlog.py          # lee el registro de la API para mostrarlo
│   ├── explain.py            # pasa estados y roles a lenguaje de cliente
│   └── static/               # la página con los botones (HTML, CSS, JS)
└── tests/
    ├── smoke.py              # prueba de humo contra la demo encendida (ver arriba)
    ├── fake_api.py           # API de mentira, solo para las pruebas automáticas
    ├── node.test.mjs         # pruebas de env.mjs, seed.mjs, setup.mjs y launch.mjs
    └── test_*.py             # pruebas automáticas
```

## Cómo se probó

**Pruebas automáticas** (no necesitan Docker ni la API verdadera; usan una API de mentira que contesta lo mismo que la real y que se puede debilitar para comprobar que cada veredicto cambia cuando la defensa falta):

```bash
pip install pytest pyyaml
python -m pytest demo/tests -q
node --test "demo/tests/*.test.mjs"
```

Cubren la generación de credenciales, el cliente de la API, cada uno de los ocho ataques (también con la defensa apagada), la consola (recorrido, rechazos, seguridad del servidor, textos), las propiedades de seguridad del `docker-compose.yml` y de los Dockerfile, la prueba de humo y que lo que dice la demo coincida con el código de la API (límites, duración de las llaves, formato del registro). No forman parte del flujo de integración continua del repositorio.

**Recorrido con la API verdadera.** Además, la API del repositorio se construyó con `next build` y se ejecutó con `next start`, como usuario sin privilegios, con su carpeta en solo lectura y sin red, junto a esta consola. Se la recorrió de dos maneras: con la prueba de humo (los 17 pasos, varias veces seguidas) y con un navegador Chromium y clics reales, en pantalla de escritorio y de celular, sin errores en la consola del navegador. En ese recorrido la base fue una réplica en memoria (la misma que usan las pruebas automáticas), no PostgreSQL. Lo que depende de Docker y de PostgreSQL (construir las imágenes, las migraciones de Prisma, `setup.mjs`, la red sin salida y los usuarios sin root dentro de los contenedores) lo cubre la prueba de aceptación de más arriba.

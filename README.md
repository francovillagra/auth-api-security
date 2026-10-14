<img src="./assets/banner.png" alt="Auth API Security" width="900" />

# Auth API Security

API REST construida con **Next.js 16**, **TypeScript** y **Prisma**, con autenticación JWT, control de acceso por roles, rate limiting por IP, múltiples capas de seguridad y logging estructurado. Cada afirmación de este README está cubierta por tests (`npm test`); lo que todavía no está resuelto figura en [Limitaciones conocidas](#limitaciones-conocidas).

---

## ¿Qué es este proyecto?

Este proyecto nació como un template profesional para APIs que necesitan autenticación segura desde el día uno. En lugar de arrancar con un CRUD básico y agregar seguridad después, este proyecto la construye como parte de la arquitectura desde el comienzo.

Incluye todo lo que normalmente se agrega a último momento: tokens de acceso y refresco, protección de rutas, roles, validación de inputs, rate limiting, headers de seguridad y logging — todo integrado y con tests.

---

## Features principales

- **Autenticación JWT** — Access tokens (15 min) + refresh tokens (7 días), firmados con HS256 (algoritmo fijado) y con emisor, audiencia y `jti`. Un refresh token no sirve como access token ni al revés
- **Secretos validados al arrancar** — La app no inicia si `JWT_SECRET` / `JWT_REFRESH_SECRET` faltan, tienen menos de 32 caracteres, parecen valores de ejemplo o son iguales entre sí
- **Roles (RBAC)** — `USER` y `ADMIN`. Las rutas de admin leen el rol **de la base en cada pedido**: un admin degradado o eliminado pierde el acceso al instante
- **Seguridad de contraseñas** — Hash bcrypt con 10 salt rounds (máximo 72 bytes, el límite real de bcrypt), nunca se almacena ni expone en texto plano
- **Login sin filtraciones** — Mismo mensaje y mismo tiempo de respuesta si el email existe o no (se compara contra un hash de relleno)
- **Rate limiting** — Ventana deslizante por IP (5 req / 10s) con Upstash Redis; fallback en memoria para desarrollo local o si Redis no responde
- **Security headers** — Equivalente a Helmet: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy. Las rutas `/api` llevan `Cache-Control: no-store` y una CSP que no carga nada
- **CORS** — Lista explícita de orígenes (`CORS_ORIGIN`); sin configurar, solo mismo origen. No se admite `*`
- **Validación con Zod** — Schemas tipados con errores por campo, emails normalizados (minúsculas), tamaños máximos y cuerpo limitado a 8 KB
- **Logging estructurado** — Winston con colores en dev, niveles por entorno. Los logs llevan ids de usuario, no emails ni contraseñas
- **Request logging** — Método, ruta, status y duración en cada respuesta; los errores inesperados responden un 500 genérico
- **Prisma ORM** — PostgreSQL

---

## Stack técnico

| Capa | Tecnología |
|---|---|
| Framework | Next.js 16 (App Router) |
| Lenguaje | TypeScript |
| ORM | Prisma 5 |
| Base de datos | PostgreSQL |
| Autenticación | jsonwebtoken + bcryptjs |
| Validación | Zod |
| Rate limiting | @upstash/ratelimit + @upstash/redis |
| Logging | Winston |
| Tests | Vitest (Prisma falso en memoria) |

---

## Arquitectura — Estructura de carpetas

```
auth-api-security/
│
├── app/api/                         # Route handlers (Next.js App Router)
│   ├── auth/
│   │   ├── login/route.ts           # POST  /api/auth/login
│   │   ├── register/route.ts        # POST  /api/auth/register
│   │   └── refresh/route.ts         # POST  /api/auth/refresh
│   ├── users/
│   │   └── me/route.ts              # GET   /api/users/me          ← protegido
│   └── admin/users/
│       ├── route.ts                 # GET   /api/admin/users       ← solo ADMIN
│       └── [id]/role/route.ts       # PATCH /api/admin/users/:id/role ← solo ADMIN
│
├── lib/                             # Utilidades del servidor
│   ├── auth.ts                      # JWT (HS256, iss/aud/jti), bcrypt, getAuthUser()
│   ├── secrets.ts                   # Validación de JWT_SECRET / JWT_REFRESH_SECRET al arrancar
│   ├── rbac.ts                      # requireRole(): 401/403 con el rol leído de la base
│   ├── http.ts                      # parseJsonBody(): Content-Type, tamaño, JSON y Zod → 415/413/400
│   ├── users.ts                     # búsqueda de usuario por email normalizado
│   ├── db.ts                        # Prisma client singleton (hot-reload safe)
│   ├── logger.ts                    # Instancia Winston + wrapper tipado
│   ├── request-logger.ts            # withLogging() HOC para route handlers
│   └── validations.ts               # Schemas Zod: register, login, refresh
│
├── prisma/
│   ├── schema.prisma                # Modelos: User (y Scan, heredado y sin uso)
│   └── migrations/                  # ⚠ Historial SQLite original: ver "Limitaciones conocidas"
│
├── tests/                           # Vitest: tokens, secretos, rutas, proxy y headers
├── proxy.ts                         # Proxy de Next (Node.js): rate limiting, guardia de /api/users y CORS
├── next.config.ts                   # Security headers
└── .env                             # Variables de entorno (no commiteado)
```

### Flujo de una request

```
Request entrante
      │
      ▼
 proxy.ts  (runtime Node.js)
      ├─ OPTIONS → 204 (preflight; headers CORS solo para orígenes de CORS_ORIGIN)
      ├─ /api/auth/* → Rate limit 5 req/10s por IP
      │       └─ Excedido → 429 + Retry-After
      ├─ /api/users/* → Verifica header Authorization
      │       └─ Falta → 401
      └─ → pasa al route handler
                    │
                    ▼
         Route Handler (Node.js Runtime)
                    ├─ withLogging() → registra método + path + status + ms (y convierte excepciones en 500 genérico)
                    ├─ parseJsonBody() → 415 / 413 / 400 (Content-Type, tamaño, JSON, Zod)
                    ├─ JWT → verifica firma, algoritmo, emisor, audiencia y vencimiento
                    ├─ requireRole() (rutas admin) → confirma usuario y rol en la base
                    └─ Prisma → consulta DB → respuesta JSON
```

---

## Requisitos previos

- Node.js >= 20
- npm >= 10
- Git

---

## Instalación paso a paso

### 1. Clonar el repositorio

```bash
git clone https://github.com/francovillagra/auth-api-security.git
cd auth-api-security
```

### 2. Instalar dependencias

```bash
npm install
```

### 3. Configurar variables de entorno

```bash
cp .env.example .env
```

Editá `.env` con tus valores (ver sección Variables de entorno). **`JWT_SECRET` y `JWT_REFRESH_SECRET` vienen vacíos a propósito**: generá cada uno con `openssl rand -base64 48`; la app no arranca sin ellos.

### 4. Crear la base de datos

Necesitás una base PostgreSQL (`DATABASE_URL` en `.env`). Para crear las tablas a partir del schema:

```bash
npx prisma db push
```

> Las carpetas de `prisma/migrations` son del primer esquema (SQLite) y no se pueden aplicar sobre PostgreSQL; hasta reemplazarlas se usa `db push`.

### 5. Iniciar el servidor

```bash
npm run dev
```

La API queda disponible en `http://localhost:3000`.

---

## Variables de entorno

| Variable | Descripción | Requerida |
|---|---|---|
| `DATABASE_URL` | Conexión a PostgreSQL | Sí |
| `JWT_SECRET` | Secreto para firmar access tokens (32+ caracteres, no de ejemplo, distinto del otro) | Sí |
| `JWT_REFRESH_SECRET` | Secreto para firmar refresh tokens (32+ caracteres, no de ejemplo, distinto del otro) | Sí |
| `NODE_ENV` | `development` o `production` | Sí |
| `CORS_ORIGIN` | Orígenes del frontend permitidos, separados por coma y sin `/` final (no se admite `*`) | No (default: ninguno, solo mismo origen) |
| `UPSTASH_REDIS_REST_URL` | URL de Upstash Redis para rate limiting en prod | No |
| `UPSTASH_REDIS_REST_TOKEN` | Token de Upstash Redis | No |

> Generá cada secreto con:
> ```bash
> openssl rand -base64 48
> ```

---

## Endpoints documentados

Todos los endpoints reciben y devuelven JSON. Los `POST`/`PATCH` exigen `Content-Type: application/json` (si no, `415`) y un cuerpo de hasta 8 KB (si no, `413`); un JSON roto o que no cumple el schema devuelve `400`.

### `POST /api/auth/register`

Registra un nuevo usuario y devuelve tokens. El email se guarda en minúsculas y sin espacios.

**Body:**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "MiPassword1",
  "name": "Juan Pérez"
}
```

Reglas: email válido de hasta 254 caracteres; contraseña de 8 a 72 bytes con al menos una mayúscula, una minúscula y un número; nombre opcional de 2 a 100 caracteres. Cualquier otro campo (por ejemplo `role`) se ignora.

**cURL:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPassword1","name":"Juan Pérez"}'
```

**Respuesta `201`:**
```json
{
  "user": { "id": "...", "email": "...", "name": "...", "role": "USER", "createdAt": "..." },
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

| Código | Causa |
|---|---|
| `201` | Usuario creado |
| `400` | Validación fallida o JSON inválido |
| `409` | Email ya registrado (sin distinguir mayúsculas) |
| `413` / `415` | Cuerpo demasiado grande / Content-Type incorrecto |
| `429` | Rate limit excedido |

---

### `POST /api/auth/login`

Autentica un usuario existente y devuelve tokens. Responde lo mismo (y tarda lo mismo) si el email no existe o la contraseña es incorrecta.

**cURL:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPassword1"}'
```

**Respuesta `200`:**
```json
{
  "user": { "id": "...", "email": "...", "name": "...", "role": "USER", "createdAt": "..." },
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

| Código | Causa |
|---|---|
| `200` | Login exitoso |
| `400` | Validación fallida o JSON inválido |
| `401` | Credenciales inválidas |
| `413` / `415` | Cuerpo demasiado grande / Content-Type incorrecto |
| `429` | Rate limit excedido |

---

### `POST /api/auth/refresh`

Devuelve un par de tokens nuevo a cambio de un refresh token válido. El rol del access token nuevo sale de la base. ⚠ El refresh token anterior **sigue siendo válido hasta que vence** (ver [Limitaciones conocidas](#limitaciones-conocidas)).

**cURL:**
```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<jwt>"}'
```

**Respuesta `200`:**
```json
{
  "accessToken": "<nuevo-jwt>",
  "refreshToken": "<nuevo-jwt>"
}
```

| Código | Causa |
|---|---|
| `200` | Tokens renovados |
| `400` | Validación fallida o JSON inválido |
| `401` | Token inválido, expirado o usuario eliminado (mismo mensaje en los tres casos) |
| `429` | Rate limit excedido |

---

### `GET /api/users/me` — Protegido

Devuelve el perfil del usuario autenticado.

**cURL:**
```bash
curl http://localhost:3000/api/users/me \
  -H "Authorization: Bearer <accessToken>"
```

**Respuesta `200`:**
```json
{
  "user": {
    "id": "...",
    "email": "...",
    "name": "...",
    "role": "USER",
    "createdAt": "...",
    "updatedAt": "..."
  }
}
```

| Código | Causa |
|---|---|
| `200` | Perfil devuelto |
| `401` | Token faltante, inválido o vencido (un refresh token no sirve) |
| `404` | Usuario eliminado |

---

### `GET /api/admin/users` — Solo `ADMIN`

Lista todos los usuarios (sin contraseñas). El rol se confirma contra la base en cada pedido.

| Código | Causa |
|---|---|
| `200` | Lista de usuarios |
| `401` | Token faltante, inválido, o el usuario ya no existe |
| `403` | El usuario no es ADMIN (el mensaje no revela roles) |

### `PATCH /api/admin/users/:id/role` — Solo `ADMIN`

Cambia el rol de un usuario. Body: `{ "role": "ADMIN" }` o `{ "role": "USER" }`. Un admin no puede quitarse el rol a sí mismo.

| Código | Causa |
|---|---|
| `200` | Rol actualizado |
| `400` | Rol inválido, JSON inválido o intento de auto-degradación |
| `401` / `403` | Igual que `GET /api/admin/users` |
| `404` | El usuario no existe |

---

## Security features detallados

### Capa 1 — Proxy (`proxy.ts`)

Primer filtro antes de que el request llegue a los route handlers (en Next 16 corre en el runtime de Node.js):

- **Rate limiting por IP**: ventana deslizante de 5 req/10s sobre `/api/auth/*` (un solo contador para login, registro y refresh). Usa Upstash Redis si está configurado; si no, o si Redis falla, usa un `Map` en memoria. Responde `429` con `Retry-After` y `X-RateLimit-*`.
- **IP del cliente**: se toma `x-real-ip` (que fija Vercel); si no existe, el **último** valor de `x-forwarded-for`, que es el que agregó el proxy de confianza (el primero lo puede escribir cualquiera). Si publicás el servicio detrás de otro proxy, revisá este dato.
- **Auth guard**: requests a `/api/users/*` sin `Authorization: Bearer ...` reciben `401` sin tocar el route handler.
- **CORS**: solo se devuelven headers `Access-Control-*` a los orígenes listados en `CORS_ORIGIN`; el preflight incluye `PATCH`. Siempre se agrega `Vary: Origin`.

### Capa 2 — Security Headers (`next.config.ts`)

| Header | Efecto |
|---|---|
| `Content-Security-Policy` | Páginas: mismo origen. Rutas `/api`: `default-src 'none'` (no cargan nada) |
| `Cache-Control: no-store` | En `/api`: las respuestas con tokens no se cachean |
| `Strict-Transport-Security` | Fuerza HTTPS por 2 años con preload |
| `X-Frame-Options: DENY` | Previene clickjacking |
| `X-Content-Type-Options: nosniff` | Previene MIME sniffing |
| `Referrer-Policy` | Limita datos en el header Referer |
| `Permissions-Policy` | Desactiva cámara, micrófono y geolocalización |
| `X-Powered-By` | Eliminado |

### Capa 3 — Validación de inputs (`lib/validations.ts`, `lib/http.ts`)

Zod valida cada body antes de tocar la DB, con tamaños máximos (email 254, nombre 100, contraseña 72 bytes) y el cuerpo completo limitado a 8 KB. Errores con detalle por campo:

```json
{
  "error": "Validation failed",
  "details": {
    "password": ["Password must contain at least one uppercase letter"]
  }
}
```

### Capa 4 — JWT, contraseñas y roles (`lib/auth.ts`, `lib/secrets.ts`, `lib/rbac.ts`)

- Access tokens: **15 minutos**. Refresh tokens: **7 días**, con `jti` único (dos tokens nunca son idénticos)
- Algoritmo fijado a **HS256** al verificar, y verificación de emisor y audiencia: un refresh token no puede usarse como access token aunque los secretos se reutilicen por error
- Secretos de **32+ caracteres**, distintos entre sí y sin aspecto de valor de ejemplo; si no, la app no arranca (el mensaje de error nunca muestra el secreto)
- Contraseñas: **bcrypt 10 rounds**, nunca retornadas en respuestas
- Login: **mismo mensaje y mismo tiempo** para email inexistente y contraseña incorrecta (bcrypt corre en ambos casos)
- Roles: las rutas `/api/admin/*` consultan usuario y rol en la base en cada pedido (401 si el usuario no existe, 403 si el rol no alcanza, sin revelar roles)

### Capa 5 — Logging (`lib/logger.ts` + `lib/request-logger.ts`)

- Winston loguea queries de Prisma en dev, solo errores en prod
- `withLogging()` registra cada request: `POST /api/auth/login 200 — 85ms`
- Las excepciones no previstas quedan logueadas y se responde un `500` genérico, sin detalles internos
- Los logs identifican personas por id, no por email, y nunca incluyen contraseñas ni tokens

---

## Limitaciones conocidas

Lo que esta API **todavía no hace** (para que nadie lo dé por hecho):

- **Los refresh tokens no se revocan.** Al renovar o hacer logout, el token anterior sigue siendo válido hasta que vence (7 días). No existe `logout`. Un token robado se puede usar hasta entonces. Es lo primero del roadmap.
- **El rate limit es por IP, no por cuenta.** Un atacante con muchas IPs puede probar contraseñas contra una misma cuenta sin que el límite lo frene. Hace falta un contador de intentos fallidos por email.
- **El registro revela si un email ya existe** (`409`). Es el comportamiento habitual sin verificación por email; el rate limit lo hace costoso de enumerar a escala.
- **La IP del cliente se asume confiable solo en Vercel.** Fuera de Vercel, quien llegue directo al servicio puede falsificar `x-real-ip`.
- **Sin verificación de email, reset de contraseña ni 2FA.**
- **Migraciones de Prisma:** `prisma/migrations` es el historial del esquema SQLite original y no corresponde al esquema actual en PostgreSQL; las tablas se crean con `prisma db push`.
- **Los tests usan un Prisma falso en memoria**, no una base real: cubren la lógica de la API pero no el SQL real.

---

## Testing

```bash
npm test          # Vitest: tokens, secretos, rutas, roles, proxy y headers
npm run typecheck # tsc --noEmit
npm run lint
```

Los tests ejecutan los route handlers reales con un Prisma falso en memoria. Cubren, entre otros: tokens con algoritmo, emisor o audiencia equivocados, secretos de ejemplo, admin degradado o eliminado, emails duplicados por mayúsculas, JSON roto, cuerpos gigantes, tiempo de respuesta del login, rate limiting y CORS.

### Flujo manual completo

```bash
# 1. Registrar
REGISTER=$(curl -s -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234","name":"Test"}')

ACCESS=$(echo $REGISTER | jq -r '.accessToken')
REFRESH=$(echo $REGISTER | jq -r '.refreshToken')

# 2. Perfil protegido
curl http://localhost:3000/api/users/me \
  -H "Authorization: Bearer $ACCESS"

# 3. Renovar tokens
curl -X POST http://localhost:3000/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}"
```

### Rate limiting

```bash
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"x@x.com","password":"WrongPass1"}')
  echo "Request $i → HTTP $STATUS"
done
# Requests 1-5: 401 | Requests 6-10: 429
```

---

## Deploy a producción

### Variables necesarias

```env
NODE_ENV="production"
JWT_SECRET="<openssl rand -base64 48>"
JWT_REFRESH_SECRET="<otro openssl rand -base64 48>"
CORS_ORIGIN="https://tudominio.com"
UPSTASH_REDIS_REST_URL="https://xxx.upstash.io"
UPSTASH_REDIS_REST_TOKEN="xxx"
DATABASE_URL="postgresql://user:pass@host:5432/db?schema=public"
```

### Base de datos

El schema ya usa PostgreSQL. Para crear las tablas en una base nueva:

```bash
npx prisma db push
```

### Deploy en Vercel

```bash
npm run build
vercel --prod
```

### Checklist antes de deployar

- [ ] Secretos JWT generados con `openssl rand -base64 48` (dos distintos); la app no arranca con valores de ejemplo
- [ ] `CORS_ORIGIN` apunta al dominio del frontend (nunca `*`)
- [ ] Upstash Redis configurado para rate limiting distribuido (la memoria no se comparte entre instancias serverless)
- [ ] `DATABASE_URL` apunta a PostgreSQL de producción
- [ ] Deploy detrás de HTTPS (requerido por HSTS)
- [ ] Al actualizar desde una versión anterior: los tokens ya emitidos dejan de ser válidos (no tienen emisor ni audiencia), así que todos los usuarios deben iniciar sesión de nuevo

---

## Roadmap

- [ ] Rotación real de refresh tokens: invalidar el anterior, detectar reutilización y logout explícito
- [x] Roles y permisos (RBAC) — `USER` y `ADMIN`
- [x] Tests automatizados (Vitest, con Prisma falso en memoria)
- [ ] Tests de integración contra una base PostgreSQL real
- [ ] Límite de intentos fallidos por cuenta
- [ ] Verificación de email al registrarse
- [ ] Reset de contraseña por email
- [ ] 2FA con TOTP (Google Authenticator)
- [ ] Documentación OpenAPI / Swagger auto-generada
- [ ] Audit log de acciones sensibles

---

## Scripts

| Comando | Descripción |
|---|---|
| `npm run dev` | Servidor de desarrollo |
| `npm run build` | Build de producción |
| `npm run start` | Servidor de producción |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript sin emitir |
| `npm test` | Tests (Vitest) |
| `npx prisma db push` | Crear/actualizar las tablas desde el schema |
| `npx prisma studio` | GUI de la base de datos |

---

## Licencia

MIT — libre para usar, modificar y distribuir.

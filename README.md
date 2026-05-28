<img src="./assets/banner.png" alt="Auth API Security" width="900" height="200" />

# Auth API Security

API REST de producción construida con **Next.js 16**, **TypeScript** y **Prisma**, con autenticación JWT, rate limiting por IP, múltiples capas de seguridad y logging estructurado.

---

## ¿Qué es este proyecto?

Este proyecto nació como un template profesional para APIs que necesitan autenticación segura desde el día uno. En lugar de arrancar con un CRUD básico y agregar seguridad después, este proyecto la construye como parte de la arquitectura desde el comienzo.

Incluye todo lo que normalmente se agrega a último momento: tokens de acceso y refresco, protección de rutas, validación de inputs, rate limiting, headers de seguridad y logging — todo integrado y funcionando.

---

## Features principales

- **Autenticación JWT** — Access tokens (15 min) + refresh tokens (7 días) con rotación automática
- **Seguridad de contraseñas** — Hash bcrypt con 10 salt rounds, nunca se almacena ni expone en texto plano
- **Rate limiting** — Ventana deslizante por IP (5 req / 10s) con Upstash Redis; fallback en memoria para desarrollo local
- **Security headers** — Equivalente a Helmet: CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy
- **CORS** — Origen configurable por variable de entorno
- **Validación con Zod** — Schemas tipados con errores detallados por campo
- **Logging estructurado** — Winston con colores en dev, niveles por entorno
- **Request logging** — Método, ruta, status y duración en cada respuesta
- **Prisma ORM** — SQLite para desarrollo, PostgreSQL-ready para producción

---

## Stack técnico

| Capa | Tecnología |
|---|---|
| Framework | Next.js 16 (App Router) |
| Lenguaje | TypeScript |
| ORM | Prisma 5 |
| Base de datos | SQLite (dev) / PostgreSQL (prod) |
| Autenticación | jsonwebtoken + bcryptjs |
| Validación | Zod |
| Rate limiting | @upstash/ratelimit + @upstash/redis |
| Logging | Winston |

---

## Arquitectura — Estructura de carpetas

```
auth-api-security/
│
├── app/api/                         # Route handlers (Next.js App Router)
│   ├── auth/
│   │   ├── login/route.ts           # POST /api/auth/login
│   │   ├── register/route.ts        # POST /api/auth/register
│   │   └── refresh/route.ts         # POST /api/auth/refresh
│   └── users/
│       └── me/route.ts              # GET  /api/users/me  ← protegido
│
├── lib/                             # Utilidades del servidor
│   ├── auth.ts                      # JWT, bcrypt, getAuthUser()
│   ├── db.ts                        # Prisma client singleton (hot-reload safe)
│   ├── logger.ts                    # Instancia Winston + wrapper tipado
│   ├── request-logger.ts            # withLogging() HOC para route handlers
│   └── validations.ts               # Schemas Zod: register, login, refresh, post
│
├── prisma/
│   ├── schema.prisma                # Modelos: User, Post
│   └── migrations/                  # Historial de migraciones SQL
│
├── proxy.ts                         # Edge proxy: rate limiting + auth guard
├── next.config.ts                   # Security headers + CORS
└── .env                             # Variables de entorno (no commiteado)
```

### Flujo de una request

```
Request entrante
      │
      ▼
 proxy.ts  (Edge Runtime — sin acceso a Node.js)
      ├─ OPTIONS → 204 (preflight CORS)
      ├─ /api/auth/* → Rate limit 5 req/10s por IP
      │       └─ Excedido → 429 + Retry-After
      ├─ /api/users/* → Verifica header Authorization
      │       └─ Falta → 401
      └─ → pasa al route handler
                    │
                    ▼
         Route Handler (Node.js Runtime)
                    ├─ withLogging() → registra método + path + status + ms
                    ├─ Zod → valida body → 400 si falla
                    ├─ JWT → verifica token completo con jsonwebtoken
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

Editá `.env` con tus valores (ver sección Variables de entorno).

### 4. Crear la base de datos

```bash
npx prisma migrate dev --name init
```

Esto crea `prisma/dev.db` con las tablas `users` y `posts`.

### 5. Iniciar el servidor

```bash
npm run dev
```

La API queda disponible en `http://localhost:3000`.

---

## Variables de entorno

| Variable | Descripción | Requerida |
|---|---|---|
| `JWT_SECRET` | Secreto para firmar access tokens | Sí |
| `JWT_REFRESH_SECRET` | Secreto para firmar refresh tokens | Sí |
| `NODE_ENV` | `development` o `production` | Sí |
| `CORS_ORIGIN` | Origen permitido en CORS | No (default: `*`) |
| `UPSTASH_REDIS_REST_URL` | URL de Upstash Redis para rate limiting en prod | No |
| `UPSTASH_REDIS_REST_TOKEN` | Token de Upstash Redis | No |

> En producción, generá secretos seguros con:
> ```bash
> openssl rand -base64 32
> ```

---

## Endpoints documentados

### `POST /api/auth/register`

Registra un nuevo usuario y devuelve tokens.

**Body:**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "MiPassword1",
  "name": "Juan Pérez"
}
```

Reglas de contraseña: mínimo 8 caracteres, al menos una mayúscula, una minúscula y un número.

**cURL:**
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPassword1","name":"Juan Pérez"}'
```

**Respuesta `201`:**
```json
{
  "user": { "id": "...", "email": "...", "name": "...", "createdAt": "..." },
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

| Código | Causa |
|---|---|
| `201` | Usuario creado |
| `400` | Validación fallida |
| `409` | Email ya registrado |

---

### `POST /api/auth/login`

Autentica un usuario existente y devuelve tokens.

**cURL:**
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario@ejemplo.com","password":"MiPassword1"}'
```

**Respuesta `200`:**
```json
{
  "user": { "id": "...", "email": "...", "name": "...", "createdAt": "..." },
  "accessToken": "<jwt>",
  "refreshToken": "<jwt>"
}
```

| Código | Causa |
|---|---|
| `200` | Login exitoso |
| `400` | Validación fallida |
| `401` | Credenciales inválidas |
| `429` | Rate limit excedido |

---

### `POST /api/auth/refresh`

Rota los tokens: devuelve un par nuevo a cambio del refresh token actual.

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
| `400` | Validación fallida |
| `401` | Token inválido, expirado o usuario eliminado |

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
    "createdAt": "...",
    "updatedAt": "..."
  }
}
```

| Código | Causa |
|---|---|
| `200` | Perfil devuelto |
| `401` | Token faltante o inválido |
| `404` | Usuario eliminado |

---

## Security features detallados

### Capa 1 — Edge Proxy (`proxy.ts`)

Primer filtro antes de que el request llegue a Node.js:

- **Rate limiting por IP**: ventana deslizante de 5 req/10s sobre `/api/auth/*`. Usa Upstash Redis si está configurado; fallback a `Map` en memoria para dev. Responde `429` con headers `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`.
- **Auth guard**: requests a `/api/users/*` sin `Authorization: Bearer ...` reciben `401` sin tocar el route handler.
- **CORS preflight**: `OPTIONS` responde `204` automáticamente.
- **X-Response-Time**: tiempo total del proxy en cada respuesta.

### Capa 2 — Security Headers (`next.config.ts`)

| Header | Efecto |
|---|---|
| `Content-Security-Policy` | Restringe recursos a mismo origen, bloquea scripts externos |
| `Strict-Transport-Security` | Fuerza HTTPS por 2 años con preload |
| `X-Frame-Options: DENY` | Previene clickjacking |
| `X-Content-Type-Options: nosniff` | Previene MIME sniffing |
| `Referrer-Policy` | Limita datos en el header Referer |
| `Permissions-Policy` | Desactiva cámara, micrófono y geolocalización |

### Capa 3 — Validación de inputs (`lib/validations.ts`)

Zod valida cada body antes de tocar la DB. Errores con detalle por campo:

```json
{
  "error": "Validation failed",
  "details": {
    "password": ["Password must contain at least one uppercase letter"]
  }
}
```

### Capa 4 — JWT y contraseñas (`lib/auth.ts`)

- Access tokens: **15 minutos** (ventana corta para minimizar daño en filtración)
- Refresh tokens: **7 días**, rotados en cada uso
- Contraseñas: **bcrypt 10 rounds**, nunca retornadas en respuestas
- Login: **mismo mensaje de error** para email inexistente y password incorrecta (previene user enumeration)

### Capa 5 — Logging (`lib/logger.ts` + `lib/request-logger.ts`)

- Winston loguea queries de Prisma en dev, solo errores en prod
- `withLogging()` registra automáticamente cada request: `POST /api/auth/login 200 — 85ms`
- Errores no capturados quedan logueados antes de responder `500`

---

## Testing

### Flujo completo

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
JWT_SECRET="<openssl rand -base64 32>"
JWT_REFRESH_SECRET="<openssl rand -base64 32>"
CORS_ORIGIN="https://tudominio.com"
UPSTASH_REDIS_REST_URL="https://xxx.upstash.io"
UPSTASH_REDIS_REST_TOKEN="xxx"
DATABASE_URL="postgresql://user:pass@host:5432/db?schema=public"
```

### Cambiar a PostgreSQL

Editar `prisma/schema.prisma`:
```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
```

Aplicar migraciones:
```bash
npx prisma migrate deploy
```

### Deploy en Vercel

```bash
npm run build
vercel --prod
```

### Checklist antes de deployar

- [ ] Secretos JWT generados con `openssl rand -base64 32`
- [ ] `CORS_ORIGIN` apunta al dominio del frontend (no `*`)
- [ ] Upstash Redis configurado para rate limiting distribuido
- [ ] `DATABASE_URL` apunta a PostgreSQL de producción
- [ ] Deploy detrás de HTTPS (requerido por HSTS)

---

## Roadmap

- [ ] Blacklist de refresh tokens (logout explícito)
- [ ] Roles y permisos (RBAC) — admin, user, moderator
- [ ] Verificación de email al registrarse
- [ ] Reset de contraseña por email
- [ ] 2FA con TOTP (Google Authenticator)
- [ ] CRUD completo de posts con paginación
- [ ] Tests de integración con Jest
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
| `npx prisma migrate dev` | Correr migraciones |
| `npx prisma studio` | GUI de la base de datos |

---

## Licencia

MIT — libre para usar, modificar y distribuir.

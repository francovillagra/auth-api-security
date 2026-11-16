# La API real de este repositorio, construida como en producción (`prisma generate` + `next build`) y servida con `next start`.
# Se construye desde la raíz del repositorio (ver docker-compose.yml: `context: ..`), por eso las rutas de abajo son de la raíz.
# Solo entra al contexto lo que figura en api.Dockerfile.dockerignore; los COPY de acá abajo nombran cada cosa, así que una carpeta
# de la computadora (node_modules, .next, un .env) nunca se mezcla con la imagen.

FROM node:22-bookworm-slim AS build

ENV NEXT_TELEMETRY_DISABLED=1 \
    CHECKPOINT_DISABLE=1
WORKDIR /app

# Prisma elige su motor de consultas según la versión de OpenSSL: la imagen "slim" no la trae.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json next.config.ts postcss.config.mjs proxy.ts ./
COPY prisma ./prisma
COPY app ./app
COPY lib ./lib

# La API valida los secretos JWT al importarse, también durante el build (la CI de este repositorio hace lo mismo). Para eso alcanza con
# valores al azar que viven solo en este paso: no quedan escritos en ninguna capa de la imagen ni en el repositorio, y los verdaderos los
# genera init.py y los pone launch.mjs al arrancar.
RUN export JWT_SECRET="$(node -e "process.stdout.write(require('crypto').randomBytes(36).toString('hex'))")" \
    && export JWT_REFRESH_SECRET="$(node -e "process.stdout.write(require('crypto').randomBytes(36).toString('hex'))")" \
    && export DATABASE_URL="postgresql://build@localhost:5432/build?schema=public" \
    && npx prisma generate \
    && npx next build

# Queda solo lo que hace falta para ejecutar (sin herramientas de desarrollo). Se vuelve a generar el cliente de Prisma por si la poda
# se lleva la carpeta que lo contiene.
RUN npm prune --omit=dev \
    && DATABASE_URL="postgresql://build@localhost:5432/build?schema=public" npx prisma generate


FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    CHECKPOINT_DISABLE=1
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/.next ./.next
COPY --from=build --chown=node:node /app/package.json /app/next.config.ts ./
COPY --from=build --chown=node:node /app/prisma ./prisma
# Los scripts de la demo (credenciales, base de práctica y arranque con copia del registro).
COPY --chown=node:node demo/env.mjs demo/seed.mjs demo/setup.mjs demo/launch.mjs ./demo/

# Sin root (el usuario `node` ya existe en la imagen).
USER node

EXPOSE 3000

CMD ["node", "demo/launch.mjs"]

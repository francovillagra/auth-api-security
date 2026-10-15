-- Línea base de PostgreSQL: las tablas que la API usaba antes de los refresh tokens revocables
-- (users y el enum Role). Reemplaza al historial SQLite original, que no se podía aplicar sobre PostgreSQL.
--
-- Base NUEVA:       `prisma migrate deploy` la aplica sola.
-- Base que ya tiene la tabla users (por ejemplo la de Supabase creada con `db push`):
--                   `prisma migrate resolve --applied 20261014120000_baseline` la marca como aplicada
--                   sin ejecutarla, y recién después `prisma migrate deploy`.

-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateTable
CREATE TABLE "users" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "name" TEXT,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

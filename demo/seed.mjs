// Los datos de práctica que se cargan en la base. Aparte de setup.mjs para poder probarlo sin base de datos ni migraciones.
import { randomBytes } from 'node:crypto';

/**
 * Carga (o repone) la cuenta de administración y los clientes de práctica. Se puede repetir sin efectos de más.
 *
 * - La cuenta de administración tiene la contraseña que generó init.py: la consola la usa cuando hace de administrador.
 * - Los clientes de práctica reciben una contraseña al azar que se descarta apenas se calcula su hash: nadie la conoce.
 *   Sirven para que la lista de usuarios no esté vacía y como "víctima" del ataque de contraseñas de la consola.
 *
 * @param prisma  cliente con `user.upsert` (el de Prisma, o uno de mentira en las pruebas)
 * @param options.seed           { admin: { email, name }, customers: [{ email, name }] } (lo escribe init.py)
 * @param options.adminPassword  contraseña de la cuenta de administración
 * @param options.hash           (contraseña) => Promise<hash>  (bcrypt con 10 rondas, igual que la API)
 */
export async function seedUsers(prisma, { seed, adminPassword, hash, makePassword = () => randomBytes(18).toString('base64url') }) {
  const adminHash = await hash(adminPassword);
  await prisma.user.upsert({
    where: { email: seed.admin.email },
    update: { password: adminHash, role: 'ADMIN', name: seed.admin.name },
    create: { email: seed.admin.email, name: seed.admin.name, role: 'ADMIN', password: adminHash },
  });
  for (const customer of seed.customers) {
    await prisma.user.upsert({
      where: { email: customer.email },
      update: {},
      create: { email: customer.email, name: customer.name, role: 'USER', password: await hash(makePassword()) },
    });
  }
}

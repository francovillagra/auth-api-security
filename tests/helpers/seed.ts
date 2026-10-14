import bcrypt from 'bcryptjs';
import type { Role } from '@prisma/client';
import { dbState } from './db-state';

export const PASSWORD = 'Passw0rdOk';

// bcrypt con costo 10 tarda ~100 ms: se calcula una sola vez por contraseña.
const hashes = new Map<string, string>();
function hashOf(password: string) {
  let hash = hashes.get(password);
  if (!hash) {
    hash = bcrypt.hashSync(password, 10);
    hashes.set(password, hash);
  }
  return hash;
}

export async function seedUser(email: string, role: Role = 'USER', password = PASSWORD) {
  const user = await dbState.prisma.user.create({
    data: { email, password: hashOf(password), name: 'Seed User', role },
    select: { id: true, email: true, role: true },
  });
  return user as { id: string; email: string; role: Role };
}

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { hashPassword, generateAccessToken, generateRefreshToken } from '@/lib/auth';
import { parseJsonBody } from '@/lib/http';
import { registerSchema } from '@/lib/validations';
import { findUserByEmail, isUniqueViolation } from '@/lib/users';
import { log } from '@/lib/logger';
import { withLogging } from '@/lib/request-logger';

async function handler(req: NextRequest) {
  const parsed = await parseJsonBody(req, registerSchema);
  if (!parsed.ok) return parsed.response;

  const { email, password, name } = parsed.data;

  if (await findUserByEmail(email)) {
    return NextResponse.json({ error: 'Email already registered' }, { status: 409 });
  }

  const hashedPassword = await hashPassword(password);

  let user;
  try {
    user = await prisma.user.create({
      data: { email, password: hashedPassword, name },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
  } catch (error) {
    // Dos registros simultáneos del mismo email: gana uno, el otro cae en el índice único.
    if (isUniqueViolation(error)) {
      return NextResponse.json({ error: 'Email already registered' }, { status: 409 });
    }
    throw error;
  }

  const payload = { userId: user.id, email: user.email, role: user.role };
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  log.info(`User registered: ${user.id}`);

  return NextResponse.json({ user, accessToken, refreshToken }, { status: 201 });
}

export const POST = withLogging(handler);

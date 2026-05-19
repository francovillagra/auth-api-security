import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getAuthUser } from '@/lib/auth';
import { log } from '@/lib/logger';

export async function GET(req: NextRequest) {
  try {
    const authUser = getAuthUser(req);
    if (!authUser) {
      return NextResponse.json({ error: 'Invalid or expired token' }, { status: 401 });
    }

    const user = await prisma.user.findUnique({
      where: { id: authUser.userId },
      select: { id: true, email: true, name: true, createdAt: true, updatedAt: true },
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    log.debug(`Profile fetched: ${user.email}`);

    return NextResponse.json({ user });
  } catch (error) {
    log.error('Get profile error', error as Error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

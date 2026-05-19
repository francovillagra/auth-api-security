import { NextRequest, NextResponse } from 'next/server';

/** Routes that require a valid Bearer token. */
const PROTECTED_PREFIXES = ['/api/users'];

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const isProtected = PROTECTED_PREFIXES.some((p) => pathname.startsWith(p));

  if (!isProtected) return NextResponse.next();

  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return NextResponse.json(
      { error: 'Authorization header required' },
      { status: 401 }
    );
  }

  // Full JWT verification happens in the route handler (Node.js runtime).
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/users/:path*'],
};

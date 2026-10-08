import { NextRequest, NextResponse } from 'next/server'
import { SESSION_COOKIE } from '@/lib/server/session'

/** Routes that never require a session: the login flow and its API routes. */
const PUBLIC_PREFIXES = ['/login', '/auth', '/api/auth']

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PREFIXES.some(p => pathname === p || pathname.startsWith(p + '/'))
}

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl

  if (isPublicPath(pathname)) {
    return NextResponse.next()
  }

  if (request.cookies.get(SESSION_COOKIE)?.value) {
    return NextResponse.next()
  }

  // API calls get a JSON 401 (the client redirects); pages go to the login form.
  if (pathname.startsWith('/api/')) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  const loginUrl = request.nextUrl.clone()
  loginUrl.pathname = '/login'
  loginUrl.search = ''
  loginUrl.searchParams.set('from', pathname + search)
  return NextResponse.redirect(loginUrl)
}

export const config = {
  matcher: [
    // Match all routes except static files and Next.js internals
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}

import { NextRequest, NextResponse } from 'next/server'

const SESSION_COOKIE = 'correlic_session'

// Public paths that don't require authentication
const PUBLIC_PATHS = ['/login', '/auth/reset-password', '/auth/verify-email', '/api/']

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some(p => pathname.startsWith(p))
}

export function proxy(request: NextRequest) {
  const url = request.nextUrl.clone()

  // Skip auth check for public paths and static assets
  if (isPublicPath(url.pathname) || url.pathname.startsWith('/_next/')) {
    return NextResponse.next()
  }

  // Check for session cookie on protected routes
  const session = request.cookies.get(SESSION_COOKIE)?.value
  if (session) {
    return NextResponse.next()
  }

  // Auto-login: if API_KEY is configured (from installer), set session cookie automatically
  const apiKey = process.env.API_KEY
  if (apiKey && apiKey.trim() !== '' && apiKey !== '<RAW_API_KEY>') {
    const response = NextResponse.next()
    response.cookies.set(SESSION_COOKIE, apiKey, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // localhost
      path: '/',
    })
    return response
  }

  // No session and no API_KEY — redirect to login
  const loginUrl = request.nextUrl.clone()
  loginUrl.pathname = '/login'
  loginUrl.searchParams.set('from', url.pathname)
  return NextResponse.redirect(loginUrl)
}

export const config = {
  matcher: [
    // Match all routes except static files and Next.js internals
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}

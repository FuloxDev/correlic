import type { NextRequest } from 'next/server'

/** Cookie that holds either a service API key or a backend session token. */
export const SESSION_COOKIE = 'correlic_session'
export const SESSION_MAX_AGE_SECONDS = 7 * 24 * 60 * 60

/** All backend traffic goes through ui-proxy, which holds the mTLS client cert. */
export const PROXY_BASE = process.env.PROXY_BASE_URL || 'http://localhost:8788'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Backend session tokens (POST /auth/sessions) are UUIDs; service API keys are not. */
export function isSessionToken(value: string): boolean {
  return UUID_RE.test(value)
}

export function isSecureRequest(request: NextRequest): boolean {
  const forwarded = request.headers.get('x-forwarded-proto')
  if (forwarded) return forwarded.split(',')[0].trim().toLowerCase() === 'https'
  return request.nextUrl.protocol === 'https:'
}

export function sessionCookieOptions(request: NextRequest) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: isSecureRequest(request),
    path: '/',
    maxAge: SESSION_MAX_AGE_SECONDS,
  }
}

export function expiredCookieOptions(request: NextRequest) {
  return { ...sessionCookieOptions(request), maxAge: 0 }
}

export function getSessionToken(request: NextRequest): string | null {
  const value = request.cookies.get(SESSION_COOKIE)?.value?.trim()
  return value ? value : null
}

export function authorizationHeader(token: string): string {
  return `Bearer ${token}`
}

/** Pull a human-readable message out of a backend error body. */
export function errorMessageFrom(text: string, fallback: string): string {
  if (!text) return fallback
  try {
    const parsed = JSON.parse(text) as { error?: unknown }
    if (typeof parsed?.error === 'string' && parsed.error) return parsed.error
  } catch {
    // not JSON
  }
  return text.length <= 200 ? text : fallback
}

import { NextRequest, NextResponse } from 'next/server'
import {
  PROXY_BASE,
  SESSION_COOKIE,
  authorizationHeader,
  expiredCookieOptions,
  getSessionToken,
  isSessionToken,
} from '@/lib/server/session'

/** Cookies written by earlier versions of the dashboard; cleared on logout. */
const LEGACY_COOKIES = ['correlic_user_email', 'correlic_key_expires']

export async function POST(request: NextRequest) {
  const token = getSessionToken(request)

  // Revoke backend sessions; service API keys are not sessions and stay valid.
  if (token && isSessionToken(token)) {
    try {
      await fetch(`${PROXY_BASE}/auth/sessions`, {
        method: 'DELETE',
        headers: { Authorization: authorizationHeader(token) },
      })
    } catch (error) {
      console.error('[auth] session revoke failed:', error instanceof Error ? error.message : 'unknown error')
    }
  }

  const response = NextResponse.json({ ok: true })
  const expired = expiredCookieOptions(request)
  response.cookies.set(SESSION_COOKIE, '', expired)
  for (const name of LEGACY_COOKIES) {
    response.cookies.set(name, '', expired)
  }
  return response
}

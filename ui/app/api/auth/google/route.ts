import { NextRequest, NextResponse } from 'next/server'
import { PROXY_BASE, SESSION_COOKIE, errorMessageFrom, sessionCookieOptions } from '@/lib/server/session'

export async function POST(request: NextRequest) {
  let body: { id_token?: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }

  const idToken = body.id_token?.trim()
  if (!idToken) {
    return NextResponse.json({ error: 'id_token required' }, { status: 400 })
  }

  let sessionRes: Response
  try {
    sessionRes = await fetch(`${PROXY_BASE}/auth/google`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id_token: idToken }),
    })
  } catch {
    return NextResponse.json({ error: 'Backend unreachable' }, { status: 502 })
  }

  const text = await sessionRes.text()
  if (!sessionRes.ok) {
    const status = sessionRes.status >= 500 ? 502 : sessionRes.status
    return NextResponse.json({ error: errorMessageFrom(text, 'Google sign-in failed') }, { status })
  }

  let session: { token?: string }
  try {
    session = JSON.parse(text)
  } catch {
    return NextResponse.json({ error: 'invalid session response' }, { status: 502 })
  }

  if (!session?.token) {
    return NextResponse.json({ error: 'session token missing' }, { status: 502 })
  }

  const response = NextResponse.json({ ok: true })
  response.cookies.set(SESSION_COOKIE, session.token, sessionCookieOptions(request))
  return response
}

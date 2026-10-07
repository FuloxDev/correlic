import { NextRequest, NextResponse } from 'next/server'

const PROXY_BASE = process.env.PROXY_BASE_URL || 'http://localhost:8788'
const SESSION_COOKIE = 'correlic_session'
const EMAIL_COOKIE = 'correlic_user_email'

export async function POST(request: NextRequest) {
  let body: { id_token: string }
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }

  if (!body.id_token?.trim()) {
    return NextResponse.json({ error: 'id_token required' }, { status: 400 })
  }

  // Forward to backend Google auth handler
  const sessionRes = await fetch(`${PROXY_BASE}/auth/google`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id_token: body.id_token }),
  })

  const text = await sessionRes.text()
  if (!sessionRes.ok) {
    let errorMessage = text || 'Google sign-in failed'
    try {
      const parsed = JSON.parse(text)
      if (parsed?.error) errorMessage = parsed.error
    } catch {
      // keep text as-is
    }
    return NextResponse.json({ error: errorMessage }, { status: sessionRes.status })
  }

  let session: any
  try {
    session = JSON.parse(text)
  } catch {
    return NextResponse.json({ error: 'invalid session response' }, { status: 502 })
  }

  if (!session?.token) {
    return NextResponse.json({ error: 'session token missing' }, { status: 502 })
  }

  const response = NextResponse.json({ ok: true })
  response.cookies.set(SESSION_COOKIE, session.token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  })
  if (session?.user?.email) {
    response.cookies.set(EMAIL_COOKIE, session.user.email, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/',
    })
  }
  return response
}

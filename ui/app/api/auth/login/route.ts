import { NextRequest, NextResponse } from 'next/server'
import {
  PROXY_BASE,
  SESSION_COOKIE,
  authorizationHeader,
  errorMessageFrom,
  sessionCookieOptions,
} from '@/lib/server/session'

// Optional remote key server. Empty (the default) means keys are validated
// only against the local backend.
const CORRELIC_API = (process.env.CORRELIC_API_URL || '').trim()

type LoginBody =
  | { mode: 'api_key'; apiKey?: string }
  | { mode: 'email'; email?: string; password?: string }

/** Ask the local backend whether this key is valid for some org. */
async function validateLocally(apiKey: string): Promise<boolean> {
  try {
    const res = await fetch(`${PROXY_BASE}/orgs/me`, {
      headers: { Authorization: authorizationHeader(apiKey) },
    })
    return res.ok
  } catch {
    return false
  }
}

/** Ask the optional remote key server. Returns null when not configured or unreachable. */
async function validateRemotely(
  apiKey: string
): Promise<{ ok: boolean; expired?: boolean } | null> {
  if (!CORRELIC_API) return null
  try {
    const res = await fetch(`${CORRELIC_API}/keys/verify`, {
      headers: { 'x-api-key': apiKey },
    })
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
    if (!res.ok) {
      return { ok: false, expired: body?.code === 'KEY_EXPIRED' }
    }
    return { ok: true }
  } catch {
    return null
  }
}

export async function POST(request: NextRequest) {
  let body: LoginBody
  try {
    body = (await request.json()) as LoginBody
  } catch {
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 })
  }

  if (body.mode === 'api_key') {
    const apiKey = body.apiKey?.trim()
    if (!apiKey) {
      return NextResponse.json({ error: 'api_key required' }, { status: 400 })
    }

    // Local backend first; the remote key server is only a fallback when configured.
    let valid = await validateLocally(apiKey)
    if (!valid) {
      const remote = await validateRemotely(apiKey)
      if (remote?.ok) {
        valid = true
      } else if (remote?.expired) {
        return NextResponse.json(
          { error: 'Your API key has expired. Ask your administrator for a new one.' },
          { status: 401 }
        )
      }
    }
    if (!valid) {
      return NextResponse.json({ error: 'Invalid or revoked API key' }, { status: 401 })
    }

    const response = NextResponse.json({ ok: true })
    response.cookies.set(SESSION_COOKIE, apiKey, sessionCookieOptions(request))
    return response
  }

  if (body.mode !== 'email') {
    return NextResponse.json({ error: 'unknown login mode' }, { status: 400 })
  }

  const email = body.email?.trim()
  // Passwords are sent exactly as typed; trimming would reject valid passwords.
  const password = body.password
  if (!email || !password) {
    return NextResponse.json({ error: 'email and password required' }, { status: 400 })
  }

  let sessionRes: Response
  try {
    sessionRes = await fetch(`${PROXY_BASE}/auth/sessions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
  } catch {
    return NextResponse.json({ error: 'Backend unreachable' }, { status: 502 })
  }

  const text = await sessionRes.text()
  if (!sessionRes.ok) {
    const status = sessionRes.status >= 500 ? 502 : sessionRes.status
    return NextResponse.json(
      { error: errorMessageFrom(text, 'invalid credentials') },
      { status }
    )
  }

  let session: { token?: string; user?: { password_reset_required?: boolean } }
  try {
    session = JSON.parse(text)
  } catch {
    return NextResponse.json({ error: 'invalid session response' }, { status: 502 })
  }

  if (!session?.token) {
    return NextResponse.json({ error: 'session token missing' }, { status: 502 })
  }

  const response = NextResponse.json({
    ok: true,
    password_reset_required: !!session?.user?.password_reset_required,
  })
  response.cookies.set(SESSION_COOKIE, session.token, sessionCookieOptions(request))
  return response
}

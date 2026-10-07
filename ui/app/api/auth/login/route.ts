import { NextRequest, NextResponse } from 'next/server'

// All backend traffic goes through ui-proxy (it holds the mTLS client cert).
const PROXY_BASE = process.env.PROXY_BASE_URL || 'http://localhost:8788'
// Optional remote key server. Empty (the default) means keys are validated
// only against the local backend.
const CORRELIC_API = (process.env.CORRELIC_API_URL || '').trim()
const SESSION_COOKIE = 'correlic_session'
const EMAIL_COOKIE = 'correlic_user_email'

type LoginBody =
  | { mode: 'api_key'; apiKey: string }
  | { mode: 'email'; email: string; password: string }

const cookieOpts = {
  httpOnly: true,
  sameSite: 'lax' as const,
  secure: process.env.NODE_ENV === 'production',
  path: '/',
}

/** Ask the local backend whether this key is valid for some org. */
async function validateLocally(apiKey: string): Promise<boolean> {
  try {
    const res = await fetch(`${PROXY_BASE}/orgs/me`, {
      headers: { Authorization: apiKey },
    })
    return res.ok
  } catch {
    return false
  }
}

/** Ask the optional remote key server. Returns null when not configured or unreachable. */
async function validateRemotely(
  apiKey: string
): Promise<{ ok: boolean; expired?: boolean; expiresAt?: string | null } | null> {
  if (!CORRELIC_API) return null
  try {
    const res = await fetch(`${CORRELIC_API}/keys/verify`, {
      headers: { 'x-api-key': apiKey },
    })
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>
    if (!res.ok) {
      return { ok: false, expired: body?.code === 'KEY_EXPIRED' }
    }
    return { ok: true, expiresAt: (body?.expiresAt as string) || null }
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

    // Local backend first; the remote key server is only a fallback when one
    // is configured.
    let valid = await validateLocally(apiKey)
    let expiresAt: string | null = null
    if (!valid) {
      const remote = await validateRemotely(apiKey)
      if (remote?.ok) {
        valid = true
        expiresAt = remote.expiresAt ?? null
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
    response.cookies.set(SESSION_COOKIE, apiKey, cookieOpts)
    if (expiresAt) {
      response.cookies.set('correlic_key_expires', expiresAt, cookieOpts)
    }
    response.cookies.delete(EMAIL_COOKIE)
    return response
  }

  const email = body.email?.trim()
  const password = body.password?.trim()
  if (!email || !password) {
    return NextResponse.json(
      { error: 'email and password required' },
      { status: 400 }
    )
  }

  const headers: HeadersInit = { 'Content-Type': 'application/json' }
  const apiKey = process.env.API_KEY
  if (apiKey && apiKey.trim() !== '' && apiKey !== '<RAW_API_KEY>') {
    headers['Authorization'] = apiKey
  }

  const sessionRes = await fetch(`${PROXY_BASE}/auth/sessions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ email, password }),
  })
  const text = await sessionRes.text()
  if (!sessionRes.ok) {
    let errorMessage = text || 'invalid credentials'
    try {
      const parsed = JSON.parse(text)
      if (parsed?.error) {
        errorMessage = parsed.error
      }
    } catch {
      // keep text as-is
    }
    return NextResponse.json(
      { error: errorMessage },
      { status: sessionRes.status }
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
  response.cookies.set(SESSION_COOKIE, session.token, cookieOpts)
  response.cookies.set(EMAIL_COOKIE, email, cookieOpts)
  return response
}

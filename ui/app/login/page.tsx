'use client'

import { Suspense, useState, useEffect, useCallback } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Script from 'next/script'
import { Card, Button, Input } from '@/component/ui'

const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || ''

interface GoogleCredentialResponse {
  credential: string
}

interface GoogleAccountsId {
  initialize(config: { client_id: string; callback: (response: GoogleCredentialResponse) => void }): void
  renderButton(parent: HTMLElement | null, options: Record<string, unknown>): void
}

declare global {
  interface Window {
    google?: { accounts?: { id?: GoogleAccountsId } }
    __googleSignInInit?: () => void
  }
}

/** Only same-origin paths may be used as a post-login destination. */
function safeReturnPath(from: string | null): string {
  if (!from || !from.startsWith('/') || from.startsWith('//') || from.startsWith('/login')) return '/'
  return from
}

async function readError(res: Response, fallback: string): Promise<string> {
  const text = await res.text()
  try {
    const parsed = JSON.parse(text) as { error?: unknown }
    if (typeof parsed?.error === 'string' && parsed.error) return parsed.error
  } catch {
    // not JSON
  }
  return text || fallback
}

function LoginForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const returnTo = safeReturnPath(searchParams.get('from'))

  const [mode, setMode] = useState<'api_key' | 'email'>('api_key')
  const [apiKey, setApiKey] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)

  const handleGoogleCallback = useCallback(async (response: GoogleCredentialResponse) => {
    setGoogleLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: response.credential }),
      })
      if (!res.ok) {
        setError(await readError(res, 'Google sign-in failed'))
        return
      }
      router.push(returnTo)
    } catch {
      setError('Google sign-in failed. Is the backend running?')
    } finally {
      setGoogleLoading(false)
    }
  }, [router, returnTo])

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID) return
    const initGoogle = () => {
      const id = window.google?.accounts?.id
      if (!id) return
      id.initialize({ client_id: GOOGLE_CLIENT_ID, callback: handleGoogleCallback })
      id.renderButton(document.getElementById('google-signin-button'), {
        theme: 'filled_black',
        size: 'large',
        width: '100%',
        text: 'signin_with',
        shape: 'pill',
      })
    }
    if (window.google?.accounts?.id) {
      initGoogle()
    } else {
      // The script's onLoad handler calls this once it has loaded.
      window.__googleSignInInit = initGoogle
    }
  }, [handleGoogleCallback])

  const handleApiKeyLogin = async () => {
    if (!apiKey.trim()) {
      setError('API key is required')
      return
    }

    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'api_key', apiKey: apiKey.trim() }),
      })
      if (!res.ok) {
        setError(await readError(res, `Error ${res.status}`))
        return
      }
      router.push(returnTo)
    } catch {
      setError('Failed to connect. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const handleEmailLogin = async () => {
    if (!email.trim()) {
      setError('Email is required')
      return
    }
    if (!password) {
      setError('Password is required')
      return
    }

    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // The password is sent exactly as typed.
        body: JSON.stringify({ mode: 'email', email: email.trim(), password }),
      })
      if (!res.ok) {
        setError(await readError(res, `Error ${res.status}`))
        return
      }

      let session: { password_reset_required?: boolean } = {}
      try {
        session = (await res.json()) as { password_reset_required?: boolean }
      } catch {
        setError('Invalid response from server')
        return
      }

      if (session.password_reset_required) {
        router.push('/auth/reset-password?email=' + encodeURIComponent(email.trim()))
      } else {
        router.push(returnTo)
      }
    } catch {
      setError('Failed to connect. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className="w-full p-8">
      {/* Logo */}
      <div className="text-center mb-8">
        <div
          className="w-16 h-16 rounded-xl mx-auto mb-4 flex items-center justify-center"
          style={{ background: 'var(--accent-muted)' }}
        >
          <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="var(--accent)" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--foreground)' }}>
          Correlic
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--foreground-muted)' }}>
          Security Platform
        </p>
      </div>

      {/* Mode Toggle */}
      <div
        className="flex rounded-lg p-1 mb-6"
        style={{ background: 'var(--background-tertiary)' }}
        role="tablist"
        aria-label="Sign-in method"
      >
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'api_key'}
          className="flex-1 py-2 text-sm font-medium rounded-md transition-all"
          style={{
            background: mode === 'api_key' ? 'var(--background-secondary)' : 'transparent',
            color: mode === 'api_key' ? 'var(--foreground)' : 'var(--foreground-muted)',
          }}
          onClick={() => setMode('api_key')}
        >
          API Key
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'email'}
          className="flex-1 py-2 text-sm font-medium rounded-md transition-all"
          style={{
            background: mode === 'email' ? 'var(--background-secondary)' : 'transparent',
            color: mode === 'email' ? 'var(--foreground)' : 'var(--foreground-muted)',
          }}
          onClick={() => setMode('email')}
        >
          Email Login
        </button>
      </div>

      {error && (
        <div
          role="alert"
          className="p-3 rounded-lg mb-4 text-sm"
          style={{ background: 'var(--critical-bg)', color: 'var(--critical)' }}
        >
          {error}
        </div>
      )}

      {mode === 'api_key' ? (
        <form className="space-y-4" onSubmit={e => { e.preventDefault(); void handleApiKeyLogin() }}>
          <Input
            id="login-api-key"
            label="API Key"
            type="password"
            autoComplete="off"
            placeholder="Enter your API key"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
          />
          <p className="text-xs" style={{ color: 'var(--foreground-subtle)' }}>
            Get your API key from your organization admin or generate one using the CLI.
          </p>
          <Button type="submit" variant="primary" className="w-full" disabled={loading}>
            {loading ? 'Connecting...' : 'Connect'}
          </Button>
        </form>
      ) : (
        <form className="space-y-4" onSubmit={e => { e.preventDefault(); void handleEmailLogin() }}>
          <Input
            id="login-email"
            label="Email"
            type="email"
            autoComplete="username"
            placeholder="you@company.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
          />
          <Input
            id="login-password"
            label="Password"
            type="password"
            autoComplete="current-password"
            placeholder="••••••••"
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
          <Button type="submit" variant="primary" className="w-full" disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </Button>
          <p className="text-xs text-center" style={{ color: 'var(--foreground-subtle)' }}>
            Email login requires a user account created by your admin.
          </p>
        </form>
      )}

      {GOOGLE_CLIENT_ID && (
        <>
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t" style={{ borderColor: 'var(--border)' }} />
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="px-2" style={{ background: 'var(--background-secondary)', color: 'var(--foreground-muted)' }}>
                or
              </span>
            </div>
          </div>

          <div className="flex justify-center">
            <div id="google-signin-button" />
          </div>

          {googleLoading && (
            <p className="text-xs text-center mt-2" style={{ color: 'var(--foreground-muted)' }}>
              Signing in with Google...
            </p>
          )}

          <Script
            src="https://accounts.google.com/gsi/client"
            strategy="afterInteractive"
            onLoad={() => {
              window.__googleSignInInit?.()
            }}
          />
        </>
      )}

      <div className="mt-8 pt-6 text-center" style={{ borderTop: '1px solid var(--border)' }}>
        <p className="text-xs" style={{ color: 'var(--foreground-subtle)' }}>
          Need help? Contact your security administrator.
        </p>
      </div>
    </Card>
  )
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  )
}

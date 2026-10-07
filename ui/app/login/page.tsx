'use client'

import { useState, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { Card, Button, Input } from '@/component/ui'
import Script from 'next/script'

const GOOGLE_CLIENT_ID = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || ''

export default function LoginPage() {
  const router = useRouter()
  const [mode, setMode] = useState<'api_key' | 'email'>('api_key')
  const [apiKey, setApiKey] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)

  const handleGoogleCallback = useCallback(async (response: any) => {
    setGoogleLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id_token: response.credential }),
      })
      const text = await res.text()
      if (!res.ok) {
        let errorMessage = text
        try {
          const parsed = JSON.parse(text)
          if (parsed?.error) errorMessage = parsed.error
        } catch {}
        setError(errorMessage || 'Google sign-in failed')
        setGoogleLoading(false)
        return
      }
      router.push('/')
    } catch {
      setError('Google sign-in failed. Is the backend running?')
    } finally {
      setGoogleLoading(false)
    }
  }, [router])

  useEffect(() => {
    if (!GOOGLE_CLIENT_ID) return
    // Initialize Google Sign-In when the script loads
    const initGoogle = () => {
      if (typeof window !== 'undefined' && (window as any).google?.accounts?.id) {
        ;(window as any).google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleCallback,
        })
        ;(window as any).google.accounts.id.renderButton(
          document.getElementById('google-signin-button'),
          {
            theme: 'filled_black',
            size: 'large',
            width: '100%',
            text: 'signin_with',
            shape: 'pill',
          }
        )
      }
    }
    // If script already loaded
    if ((window as any).google?.accounts?.id) {
      initGoogle()
    } else {
      // Wait for script to load
      ;(window as any).__googleSignInInit = initGoogle
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
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ mode: 'api_key', apiKey: apiKey.trim() }),
      })

      const text = await res.text()
      if (!res.ok) {
        setError(text || `Error ${res.status}`)
        setLoading(false)
        return
      }

      router.push('/')
    } catch (err) {
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
    if (!password.trim()) {
      setError('Password is required')
      return
    }

    setLoading(true)
    setError('')

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          mode: 'email',
          email: email.trim(),
          password: password.trim(),
        }),
      })

      const text = await res.text()
      console.log('[Login] Session response status:', res.status)
      console.log('[Login] Session response body:', text)

      if (!res.ok) {
        let errorMessage = text || `Error: ${res.status}`
        try {
          const parsed = JSON.parse(text)
          if (parsed?.error) {
            errorMessage = parsed.error
          }
        } catch {
          // keep text as-is
        }
        setError(errorMessage)
        setLoading(false)
        return
      }

      let session
      try {
        session = JSON.parse(text)
      } catch (e) {
        console.error('[Login] Failed to parse session JSON:', e, 'Body:', text)
        setError(`Invalid response from server: ${text.substring(0, 100)}`)
        setLoading(false)
        return
      }

      if (session.password_reset_required) {
        router.push('/auth/reset-password?email=' + encodeURIComponent(email.trim()))
      } else {
        router.push('/')
      }
    } catch (err) {
      setError('Failed to connect. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div 
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: 'var(--background)' }}
    >
      <Card className="w-full max-w-md p-8">
        {/* Logo */}
        <div className="text-center mb-8">
          <div 
            className="w-16 h-16 rounded-xl mx-auto mb-4 flex items-center justify-center"
            style={{ background: 'var(--accent-muted)' }}
          >
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="var(--accent)">
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
        >
          <button
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

        {/* Error */}
        {error && (
          <div 
            className="p-3 rounded-lg mb-4 text-sm"
            style={{ background: 'var(--critical-bg)', color: 'var(--critical)' }}
          >
            {error}
          </div>
        )}

        {/* Form */}
        {mode === 'api_key' ? (
          <div className="space-y-4">
            <Input
              label="API Key"
              type="password"
              placeholder="Enter your API key"
              value={apiKey}
              onChange={e => setApiKey(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleApiKeyLogin()}
            />
            <p className="text-xs" style={{ color: 'var(--foreground-subtle)' }}>
              Get your API key from your organization admin or generate one using the CLI.
            </p>
            <Button
              variant="primary"
              className="w-full"
              disabled={loading}
              onClick={handleApiKeyLogin}
            >
              {loading ? 'Connecting...' : 'Connect'}
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            <Input
              label="Email"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
            <Input
              label="Password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleEmailLogin()}
            />
            <Button
              variant="primary"
              className="w-full"
              disabled={loading}
              onClick={handleEmailLogin}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
            <p className="text-xs text-center" style={{ color: 'var(--foreground-subtle)' }}>
              Email login requires a user account created by your admin.
            </p>
          </div>
        )}

        {/* Google Sign-In */}
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
                if ((window as any).__googleSignInInit) {
                  ;(window as any).__googleSignInInit()
                }
              }}
            />
          </>
        )}

        {/* Footer */}
        <div className="mt-8 pt-6 text-center" style={{ borderTop: '1px solid var(--border)' }}>
          <p className="text-xs" style={{ color: 'var(--foreground-subtle)' }}>
            Need help? Contact your security administrator.
          </p>
        </div>
      </Card>
    </div>
  )
}

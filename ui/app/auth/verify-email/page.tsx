'use client'

import { useState, useEffect, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Card, Button } from '@/component/ui'
import { CheckCircle, XCircle, Loader2, Mail } from 'lucide-react'

type Status = 'verifying' | 'success' | 'error' | 'no-token'

function VerifyEmailContent() {
    const searchParams = useSearchParams()
    const router = useRouter()
    const token = searchParams.get('token')

    const [status, setStatus] = useState<Status>(token ? 'verifying' : 'no-token')
    const [message, setMessage] = useState('')
    const [email, setEmail] = useState('')

    useEffect(() => {
        if (!token) return
        let cancelled = false

        fetch('/api/proxy/auth/email/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ token }),
        })
            .then(async res => {
                const data = (await res.json().catch(() => ({}))) as { error?: string; email?: string; message?: string }
                if (cancelled) return
                if (!res.ok) {
                    setStatus('error')
                    setMessage(data.error || 'Verification failed')
                    return
                }
                setStatus('success')
                setEmail(data.email || '')
                setMessage(data.message || 'Email verified successfully')
            })
            .catch(() => {
                if (cancelled) return
                setStatus('error')
                setMessage('Failed to verify email. Please try again.')
            })

        return () => {
            cancelled = true
        }
    }, [token])

    return (
        <Card className="w-full p-8 text-center">
            {status === 'verifying' && (
                <>
                    <Loader2
                        className="w-16 h-16 mx-auto mb-4 animate-spin"
                        style={{ color: 'var(--accent)' }}
                        aria-hidden="true"
                    />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Verifying your email...
                    </h1>
                    <p className="text-sm" style={{ color: 'var(--foreground-muted)' }}>
                        Please wait while we verify your email address.
                    </p>
                </>
            )}

            {status === 'success' && (
                <>
                    <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400" aria-hidden="true" />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Email Verified!
                    </h1>
                    <p className="text-sm mb-6" style={{ color: 'var(--foreground-muted)' }}>
                        {email ? (
                            <>Your email <strong>{email}</strong> has been verified successfully.</>
                        ) : (
                            'Your email has been verified successfully.'
                        )}
                    </p>
                    <Button variant="primary" className="w-full" onClick={() => router.push('/login')}>
                        Continue to Login
                    </Button>
                </>
            )}

            {status === 'error' && (
                <>
                    <XCircle className="w-16 h-16 mx-auto mb-4 text-red-400" aria-hidden="true" />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Verification Failed
                    </h1>
                    <p className="text-sm mb-6" style={{ color: 'var(--foreground-muted)' }}>
                        {message}
                    </p>
                    <Button variant="primary" className="w-full" onClick={() => router.push('/login')}>
                        Back to Login
                    </Button>
                </>
            )}

            {status === 'no-token' && (
                <>
                    <Mail className="w-16 h-16 mx-auto mb-4" style={{ color: 'var(--accent)' }} aria-hidden="true" />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Check Your Email
                    </h1>
                    <p className="text-sm mb-6" style={{ color: 'var(--foreground-muted)' }}>
                        We sent you a verification link. Click the link in your email to verify your account.
                    </p>
                    <Button variant="primary" className="w-full" onClick={() => router.push('/login')}>
                        Back to Login
                    </Button>
                </>
            )}
        </Card>
    )
}

export default function VerifyEmailPage() {
    return (
        <Suspense
            fallback={
                <Card className="w-full p-8 text-center">
                    <Loader2 className="w-16 h-16 mx-auto mb-4 animate-spin" style={{ color: 'var(--accent)' }} aria-hidden="true" />
                    <p className="text-sm" style={{ color: 'var(--foreground-muted)' }}>Loading...</p>
                </Card>
            }
        >
            <VerifyEmailContent />
        </Suspense>
    )
}

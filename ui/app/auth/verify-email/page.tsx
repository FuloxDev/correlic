'use client'

import { useState, useEffect, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Card, Button } from '@/component/ui'
import { CheckCircle, XCircle, Loader2, Mail } from 'lucide-react'

function VerifyEmailContent() {
    const searchParams = useSearchParams()
    const router = useRouter()
    const token = searchParams.get('token')

    const [status, setStatus] = useState<'verifying' | 'success' | 'error' | 'no-token'>('verifying')
    const [message, setMessage] = useState('')
    const [email, setEmail] = useState('')

    useEffect(() => {
        if (!token) {
            setStatus('no-token')
            return
        }

        verifyToken(token)
    }, [token])

    async function verifyToken(t: string) {
        setStatus('verifying')
        try {
            const res = await fetch('/api/proxy/auth/email/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ token: t }),
            })
            const data = await res.json()

            if (!res.ok) {
                setStatus('error')
                setMessage(data.error || 'Verification failed')
                return
            }

            setStatus('success')
            setEmail(data.email || '')
            setMessage(data.message || 'Email verified successfully')
        } catch {
            setStatus('error')
            setMessage('Failed to verify email. Please try again.')
        }
    }

    return (
        <Card className="w-full max-w-md p-8 text-center">
            {status === 'verifying' && (
                <>
                    <Loader2
                        className="w-16 h-16 mx-auto mb-4 animate-spin"
                        style={{ color: 'var(--accent)' }}
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
                    <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400" />
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
                    <Button
                        variant="primary"
                        className="w-full"
                        onClick={() => router.push('/login')}
                    >
                        Continue to Login
                    </Button>
                </>
            )}

            {status === 'error' && (
                <>
                    <XCircle className="w-16 h-16 mx-auto mb-4 text-red-400" />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Verification Failed
                    </h1>
                    <p className="text-sm mb-6" style={{ color: 'var(--foreground-muted)' }}>
                        {message}
                    </p>
                    <Button
                        variant="primary"
                        className="w-full"
                        onClick={() => router.push('/login')}
                    >
                        Back to Login
                    </Button>
                </>
            )}

            {status === 'no-token' && (
                <>
                    <Mail
                        className="w-16 h-16 mx-auto mb-4"
                        style={{ color: 'var(--accent)' }}
                    />
                    <h1 className="text-xl font-bold mb-2" style={{ color: 'var(--foreground)' }}>
                        Check Your Email
                    </h1>
                    <p className="text-sm mb-6" style={{ color: 'var(--foreground-muted)' }}>
                        We sent you a verification link. Click the link in your email to verify your account.
                    </p>
                    <Button
                        variant="primary"
                        className="w-full"
                        onClick={() => router.push('/login')}
                    >
                        Back to Login
                    </Button>
                </>
            )}
        </Card>
    )
}

export default function VerifyEmailPage() {
    return (
        <div
            className="min-h-screen flex items-center justify-center p-4"
            style={{ background: 'var(--background)' }}
        >
            <Suspense
                fallback={
                    <Card className="w-full max-w-md p-8 text-center">
                        <Loader2
                            className="w-16 h-16 mx-auto mb-4 animate-spin"
                            style={{ color: 'var(--accent)' }}
                        />
                        <p className="text-sm" style={{ color: 'var(--foreground-muted)' }}>Loading...</p>
                    </Card>
                }
            >
                <VerifyEmailContent />
            </Suspense>
        </div>
    )
}

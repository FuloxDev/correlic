'use client'

import { Suspense, useEffect, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Card, Button, Input } from '@/component/ui'
import { useToast } from '@/component/ToastProvider'
import { fetchJSON } from '@/lib/api'
import { LoadingState } from '@/component/LoadingState'

function ResetPasswordPageInner() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { showToast } = useToast()
  
  const [email, setEmail] = useState('')
  const [oldPassword, setOldPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const emailParam = searchParams.get('email')
    if (emailParam) {
      setEmail(emailParam)
    }
  }, [searchParams])

  const handleReset = async () => {
    if (!email.trim()) {
      setError('Email is required')
      return
    }
    if (!oldPassword.trim()) {
      setError('Current password is required')
      return
    }
    if (!newPassword.trim()) {
      setError('New password is required')
      return
    }
    if (newPassword.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    setError('')

    try {
      const res = await fetchJSON<{ success: boolean; message: string }>('/auth/password/reset', {
        method: 'POST',
        body: JSON.stringify({
          email: email.trim(),
          old_password: oldPassword.trim() || undefined,
          new_password: newPassword.trim(),
        }),
      })

      showToast('Password updated successfully', 'success')
      router.push('/login')
    } catch (err: any) {
      setError(err.message || 'Failed to reset password')
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
        <div className="text-center mb-8">
          <div 
            className="w-16 h-16 rounded-xl mx-auto mb-4 flex items-center justify-center"
            style={{ background: 'var(--accent-muted)' }}
          >
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="var(--accent)">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.75 5.25a3 3 0 013 3m3 0a6.75 6.75 0 01-7.5 7.5H13m-3.75-3.75H5.25A2.25 2.25 0 013 12v-1.5m18 0A2.25 2.25 0 0018.75 9H15m-3.75 3.75h6.375M15 9.75H9m12-3.75V9.75m0 0V12m0-2.25V9.75m0 2.25H21m-3.75 0H18.75" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--foreground)' }}>
            Reset Password
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--foreground-muted)' }}>
            Set a new password for your account
          </p>
        </div>

        {error && (
          <div 
            className="p-3 rounded-lg mb-4 text-sm"
            style={{ background: 'var(--critical-bg)', color: 'var(--critical)' }}
          >
            {error}
          </div>
        )}

        <div className="space-y-4">
          <Input
            label="Email"
            type="email"
            placeholder="you@company.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            disabled={!!searchParams.get('email')}
          />
          <Input
            label="Current Password"
            type="password"
            placeholder="••••••••"
            value={oldPassword}
            onChange={e => setOldPassword(e.target.value)}
          />
          <Input
            label="New Password"
            type="password"
            placeholder="At least 8 characters"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
          />
          <Input
            label="Confirm New Password"
            type="password"
            placeholder="••••••••"
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleReset()}
          />
          <Button
            variant="primary"
            className="w-full"
            disabled={loading}
            onClick={handleReset}
          >
            {loading ? 'Updating...' : 'Update Password'}
          </Button>
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => router.push('/login')}
          >
            Back to Login
          </Button>
        </div>
      </Card>
    </div>
  )
}

export default function ResetPasswordPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <ResetPasswordPageInner />
    </Suspense>
  )
}

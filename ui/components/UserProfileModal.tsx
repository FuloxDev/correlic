'use client'

import { useState, useEffect, useRef } from 'react'
import { X, Camera, Mail, CheckCircle, AlertCircle, Loader2, LogOut, Shield } from 'lucide-react'
import { getUserProfile, updateUserProfile, sendVerificationEmail, type UserProfile } from '@/lib/api-client'
import { useRouter } from 'next/navigation'

interface UserProfileModalProps {
    open: boolean
    onClose: () => void
}

export default function UserProfileModal({ open, onClose }: UserProfileModalProps) {
    const router = useRouter()
    const [profile, setProfile] = useState<UserProfile | null>(null)
    const [loading, setLoading] = useState(true)
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState('')

    // Form state
    const [name, setName] = useState('')
    const [username, setUsername] = useState('')
    const [avatarUrl, setAvatarUrl] = useState('')

    // Password change
    const [showPasswordChange, setShowPasswordChange] = useState(false)
    const [oldPassword, setOldPassword] = useState('')
    const [newPassword, setNewPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [passwordError, setPasswordError] = useState('')
    const [passwordSaving, setPasswordSaving] = useState(false)

    // Email verification
    const [verificationSent, setVerificationSent] = useState(false)
    const [sendingVerification, setSendingVerification] = useState(false)

    const modalRef = useRef<HTMLDivElement>(null)

    useEffect(() => {
        if (!open) return
        let cancelled = false
        getUserProfile()
            .then(data => {
                if (cancelled) return
                setProfile(data)
                setName(data.name || '')
                setUsername(data.username || '')
                setAvatarUrl(data.avatar_url || '')
                setError('')
            })
            .catch(() => { if (!cancelled) setError('Failed to load profile') })
            .finally(() => { if (!cancelled) setLoading(false) })
        return () => { cancelled = true }
    }, [open])

    // Close on Escape
    useEffect(() => {
        function handleKeyDown(e: KeyboardEvent) {
            if (e.key === 'Escape') onClose()
        }
        if (open) {
            document.addEventListener('keydown', handleKeyDown)
            return () => document.removeEventListener('keydown', handleKeyDown)
        }
    }, [open, onClose])

    async function handleSave() {
        setSaving(true)
        setError('')
        setSuccess('')
        try {
            const updated = await updateUserProfile({
                name: name.trim(),
                username: username.trim(),
                avatar_url: avatarUrl.trim(),
            })
            setProfile(updated)
            setSuccess('Profile updated')
            setTimeout(() => setSuccess(''), 3000)
        } catch (err: unknown) {
            let msg = 'Failed to update profile'
            const body = (err as { body?: string })?.body
            if (body) {
                try { msg = JSON.parse(body)?.error || msg } catch { /* non-JSON error body */ }
            }
            setError(msg)
        } finally {
            setSaving(false)
        }
    }

    async function handlePasswordChange() {
        setPasswordError('')
        if (newPassword.length < 8) {
            setPasswordError('Password must be at least 8 characters')
            return
        }
        if (newPassword !== confirmPassword) {
            setPasswordError('Passwords do not match')
            return
        }

        setPasswordSaving(true)
        try {
            const res = await fetch('/api/proxy/auth/password/reset', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    email: profile?.email,
                    old_password: oldPassword,
                    new_password: newPassword,
                }),
            })
            if (!res.ok) {
                const data = await res.json().catch(() => ({}))
                setPasswordError(data.error || 'Failed to change password')
                return
            }
            setShowPasswordChange(false)
            setOldPassword('')
            setNewPassword('')
            setConfirmPassword('')
            setSuccess('Password changed')
            setTimeout(() => setSuccess(''), 3000)
        } catch {
            setPasswordError('Failed to change password')
        } finally {
            setPasswordSaving(false)
        }
    }

    async function handleSendVerification() {
        setSendingVerification(true)
        try {
            await sendVerificationEmail(profile?.email)
            setVerificationSent(true)
        } catch {
            setError('Failed to send verification email')
        } finally {
            setSendingVerification(false)
        }
    }

    async function handleLogout() {
        try {
            await fetch('/api/auth/logout', { method: 'POST' })
            router.push('/login')
        } catch {
            router.push('/login')
        }
    }

    if (!open) return null

    const initials = (profile?.name || profile?.email || '?')
        .split(' ')
        .map(w => w[0])
        .join('')
        .slice(0, 2)
        .toUpperCase()

    return (
        <div className="fixed inset-0 z-[100] flex items-center justify-center" role="dialog" aria-modal="true" aria-label="Profile">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal */}
            <div
                ref={modalRef}
                className="relative z-10 w-full max-w-lg mx-4 rounded-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200"
                style={{
                    backgroundColor: 'var(--theme-card, #1a1a2e)',
                    border: '1px solid var(--theme-card-border, rgba(255,255,255,0.1))',
                    boxShadow: '0 25px 50px -12px rgba(0,0,0,0.5)',
                }}
            >
                {/* Close button */}
                <button
                    type="button"
                    onClick={onClose}
                    className="absolute top-4 right-4 p-2 rounded-lg hover:bg-white/10 transition-all z-10"
                    style={{ color: 'var(--theme-text-muted)' }}
                    aria-label="Close profile"
                >
                    <X className="w-5 h-5" aria-hidden="true" />
                </button>

                {loading ? (
                    <div className="flex items-center justify-center py-20">
                        <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--theme-accent)' }} />
                    </div>
                ) : (
                    <div className="p-8">
                        {/* Header with Avatar */}
                        <div className="flex flex-col items-center mb-8">
                            <div className="relative group mb-4">
                                {avatarUrl ? (
                                    <img
                                        src={avatarUrl}
                                        alt="Profile"
                                        className="w-24 h-24 rounded-full object-cover border-2"
                                        style={{ borderColor: 'var(--theme-accent)' }}
                                    />
                                ) : (
                                    <div
                                        className="w-24 h-24 rounded-full flex items-center justify-center text-2xl font-bold"
                                        style={{
                                            background: 'linear-gradient(135deg, var(--theme-avatar-from, #f59e0b), var(--theme-avatar-to, #d97706))',
                                        }}
                                    >
                                        {initials}
                                    </div>
                                )}
                                <div className="absolute inset-0 rounded-full bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center cursor-pointer">
                                    <Camera className="w-6 h-6 text-white" />
                                </div>
                            </div>
                            <h2 className="text-xl font-bold" style={{ color: 'var(--theme-text-primary)' }}>
                                {profile?.name || profile?.email}
                            </h2>
                            {profile?.role && (
                                <div className="flex items-center gap-1.5 mt-1">
                                    <Shield className="w-3.5 h-3.5" style={{ color: 'var(--theme-accent)' }} />
                                    <span className="text-xs font-medium capitalize" style={{ color: 'var(--theme-accent)' }}>
                                        {profile.role}
                                    </span>
                                </div>
                            )}
                        </div>

                        {/* Status messages */}
                        {error && (
                            <div className="mb-4 p-3 rounded-lg text-sm bg-red-500/10 border border-red-500/30 text-red-400">
                                {error}
                            </div>
                        )}
                        {success && (
                            <div className="mb-4 p-3 rounded-lg text-sm bg-green-500/10 border border-green-500/30 text-green-400">
                                {success}
                            </div>
                        )}

                        {/* Email with verification badge */}
                        <div className="mb-6">
                            <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--theme-text-muted)' }}>
                                Email
                            </label>
                            <div
                                className="flex items-center justify-between px-4 py-3 rounded-xl"
                                style={{
                                    backgroundColor: 'rgba(255,255,255,0.03)',
                                    border: '1px solid rgba(255,255,255,0.08)',
                                }}
                            >
                                <div className="flex items-center gap-2">
                                    <Mail className="w-4 h-4" style={{ color: 'var(--theme-text-muted)' }} />
                                    <span className="text-sm" style={{ color: 'var(--theme-text-primary)' }}>
                                        {profile?.email}
                                    </span>
                                </div>
                                {profile?.email_verified ? (
                                    <div className="flex items-center gap-1 text-green-400">
                                        <CheckCircle className="w-4 h-4" />
                                        <span className="text-xs">Verified</span>
                                    </div>
                                ) : (
                                    <div className="flex items-center gap-2">
                                        <div className="flex items-center gap-1 text-yellow-400">
                                            <AlertCircle className="w-4 h-4" />
                                            <span className="text-xs">Unverified</span>
                                        </div>
                                        {verificationSent ? (
                                            <span className="text-xs text-green-400">Sent!</span>
                                        ) : (
                                            <button
                                                onClick={handleSendVerification}
                                                disabled={sendingVerification}
                                                className="text-xs px-2 py-1 rounded-lg transition-all"
                                                style={{
                                                    backgroundColor: 'var(--theme-accent-dim)',
                                                    color: 'var(--theme-accent)',
                                                    border: '1px solid var(--theme-card-border)',
                                                }}
                                            >
                                                {sendingVerification ? 'Sending...' : 'Verify'}
                                            </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Editable fields */}
                        <div className="space-y-4 mb-6">
                            <div>
                                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--theme-text-muted)' }}>
                                    Display Name
                                </label>
                                <input
                                    type="text"
                                    value={name}
                                    onChange={e => setName(e.target.value)}
                                    placeholder="Your display name"
                                    className="w-full px-4 py-3 rounded-xl text-sm focus:outline-none transition-all"
                                    style={{
                                        backgroundColor: 'rgba(255,255,255,0.05)',
                                        border: '1px solid rgba(255,255,255,0.1)',
                                        color: 'var(--theme-text-primary)',
                                    }}
                                />
                            </div>
                            <div>
                                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--theme-text-muted)' }}>
                                    Username
                                </label>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    placeholder="@username"
                                    className="w-full px-4 py-3 rounded-xl text-sm focus:outline-none transition-all"
                                    style={{
                                        backgroundColor: 'rgba(255,255,255,0.05)',
                                        border: '1px solid rgba(255,255,255,0.1)',
                                        color: 'var(--theme-text-primary)',
                                    }}
                                />
                            </div>
                            <div>
                                <label className="text-xs font-medium mb-1.5 block" style={{ color: 'var(--theme-text-muted)' }}>
                                    Avatar URL
                                </label>
                                <input
                                    type="url"
                                    value={avatarUrl}
                                    onChange={e => setAvatarUrl(e.target.value)}
                                    placeholder="https://example.com/avatar.jpg"
                                    className="w-full px-4 py-3 rounded-xl text-sm focus:outline-none transition-all"
                                    style={{
                                        backgroundColor: 'rgba(255,255,255,0.05)',
                                        border: '1px solid rgba(255,255,255,0.1)',
                                        color: 'var(--theme-text-primary)',
                                    }}
                                />
                            </div>
                        </div>

                        {/* Save button */}
                        <button
                            onClick={handleSave}
                            disabled={saving}
                            className="w-full py-3 rounded-xl font-semibold text-sm transition-all duration-200 mb-4"
                            style={{
                                background: 'linear-gradient(135deg, var(--theme-accent, #f59e0b), var(--theme-avatar-to, #d97706))',
                                color: '#000',
                                opacity: saving ? 0.6 : 1,
                            }}
                        >
                            {saving ? 'Saving...' : 'Save Changes'}
                        </button>

                        {/* Password change section */}
                        <div
                            className="rounded-xl p-4 mb-4"
                            style={{
                                backgroundColor: 'rgba(255,255,255,0.03)',
                                border: '1px solid rgba(255,255,255,0.08)',
                            }}
                        >
                            {!showPasswordChange ? (
                                <button
                                    onClick={() => setShowPasswordChange(true)}
                                    className="text-sm font-medium transition-all"
                                    style={{ color: 'var(--theme-accent)' }}
                                >
                                    Change Password
                                </button>
                            ) : (
                                <div className="space-y-3">
                                    <h3 className="text-sm font-semibold" style={{ color: 'var(--theme-text-primary)' }}>
                                        Change Password
                                    </h3>
                                    {passwordError && (
                                        <p className="text-xs text-red-400">{passwordError}</p>
                                    )}
                                    <input
                                        type="password"
                                        value={oldPassword}
                                        onChange={e => setOldPassword(e.target.value)}
                                        placeholder="Current password"
                                        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none"
                                        style={{
                                            backgroundColor: 'rgba(255,255,255,0.05)',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            color: 'var(--theme-text-primary)',
                                        }}
                                    />
                                    <input
                                        type="password"
                                        value={newPassword}
                                        onChange={e => setNewPassword(e.target.value)}
                                        placeholder="New password (min 8 chars)"
                                        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none"
                                        style={{
                                            backgroundColor: 'rgba(255,255,255,0.05)',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            color: 'var(--theme-text-primary)',
                                        }}
                                    />
                                    <input
                                        type="password"
                                        value={confirmPassword}
                                        onChange={e => setConfirmPassword(e.target.value)}
                                        placeholder="Confirm new password"
                                        className="w-full px-3 py-2 rounded-lg text-sm focus:outline-none"
                                        style={{
                                            backgroundColor: 'rgba(255,255,255,0.05)',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            color: 'var(--theme-text-primary)',
                                        }}
                                    />
                                    <div className="flex gap-2">
                                        <button
                                            onClick={handlePasswordChange}
                                            disabled={passwordSaving || !oldPassword || !newPassword}
                                            className="px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50"
                                            style={{
                                                backgroundColor: 'var(--theme-accent-dim)',
                                                color: 'var(--theme-accent)',
                                                border: '1px solid var(--theme-card-border)',
                                            }}
                                        >
                                            {passwordSaving ? 'Changing...' : 'Update Password'}
                                        </button>
                                        <button
                                            onClick={() => {
                                                setShowPasswordChange(false)
                                                setPasswordError('')
                                                setOldPassword('')
                                                setNewPassword('')
                                                setConfirmPassword('')
                                            }}
                                            className="px-4 py-2 rounded-lg text-sm font-medium hover:bg-white/10 transition-all"
                                            style={{ color: 'var(--theme-text-muted)' }}
                                        >
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>

                        {/* Logout button */}
                        <button
                            onClick={handleLogout}
                            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-sm font-medium transition-all hover:bg-red-500/10 border"
                            style={{
                                color: '#ef4444',
                                borderColor: 'rgba(239,68,68,0.2)',
                            }}
                        >
                            <LogOut className="w-4 h-4" />
                            Sign Out
                        </button>
                    </div>
                )}
            </div>
        </div>
    )
}

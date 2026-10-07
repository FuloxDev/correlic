'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { Eye, EyeOff, Shield, ArrowRight, Lock } from 'lucide-react'
import { Logo } from '@/components/ui/Logo'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

/* ─── Animated side border ─────────────────────────────────────────────────── */

function SideBorder({ side }: { side: 'left' | 'right' }) {
  return (
    <div
      className={`fixed ${side}-0 top-0 bottom-0 w-16 xl:w-20 hidden lg:flex flex-col items-center justify-center gap-0 pointer-events-none z-10`}
    >
      {/* Glowing vertical line */}
      <div
        className="absolute inset-y-0 w-[1px]"
        style={{
          left: side === 'left' ? '50%' : undefined,
          right: side === 'right' ? '50%' : undefined,
          background: 'linear-gradient(180deg, transparent 5%, rgba(147,51,234,0.2) 30%, rgba(147,51,234,0.35) 50%, rgba(147,51,234,0.2) 70%, transparent 95%)',
          boxShadow: '0 0 8px rgba(147,51,234,0.15)',
        }}
      />

      {/* Flowing particle */}
      <motion.div
        className="absolute w-1.5 h-1.5 rounded-full"
        style={{
          left: side === 'left' ? 'calc(50% - 3px)' : undefined,
          right: side === 'right' ? 'calc(50% - 3px)' : undefined,
          background: '#9333ea',
          boxShadow: '0 0 10px #9333ea, 0 0 20px rgba(147,51,234,0.4)',
        }}
        animate={{ top: ['5%', '95%', '5%'] }}
        transition={{ duration: 8, repeat: Infinity, ease: 'easeInOut' }}
      />

      {/* Second particle going opposite */}
      <motion.div
        className="absolute w-1 h-1 rounded-full"
        style={{
          left: side === 'left' ? 'calc(50% - 2px)' : undefined,
          right: side === 'right' ? 'calc(50% - 2px)' : undefined,
          background: '#a855f7',
          boxShadow: '0 0 8px #a855f7, 0 0 16px rgba(168,85,247,0.3)',
        }}
        animate={{ top: ['90%', '10%', '90%'] }}
        transition={{ duration: 6, repeat: Infinity, ease: 'easeInOut', delay: 1 }}
      />

    </div>
  )
}

/* ─── Floating background orbs ─────────────────────────────────────────────── */

function FloatingOrbs() {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      <motion.div
        className="absolute w-[500px] h-[500px] rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(147,51,234,0.06) 0%, transparent 70%)',
          top: '10%',
          left: '-10%',
        }}
        animate={{ x: [0, 40, 0], y: [0, 30, 0] }}
        transition={{ duration: 12, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute w-[400px] h-[400px] rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 70%)',
          bottom: '5%',
          right: '-5%',
        }}
        animate={{ x: [0, -30, 0], y: [0, -20, 0] }}
        transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
      />
      <motion.div
        className="absolute w-[300px] h-[300px] rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(0,230,118,0.03) 0%, transparent 70%)',
          top: '40%',
          right: '20%',
        }}
        animate={{ x: [0, 20, 0], y: [0, -25, 0] }}
        transition={{ duration: 14, repeat: Infinity, ease: 'easeInOut', delay: 4 }}
      />
    </div>
  )
}

/* ─── Main Login Page ──────────────────────────────────────────────────────── */

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [focused, setFocused] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const { data, error: err } = await api<{ accessToken: string; user: { id: string; name: string; email: string; role: string; status: string } }>('/auth/login', {
      method: 'POST',
      body: { email, password },
    })

    setLoading(false)

    if (err || !data) {
      setError(err || 'Login failed')
      return
    }

    localStorage.setItem('correlic_token', data.accessToken)
    router.push('/account')
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 relative">
      <FloatingOrbs />
      <SideBorder side="left" />
      <SideBorder side="right" />

      <motion.div
        className="w-full max-w-md space-y-8 relative z-10"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
      >
        {/* Logo + heading */}
        <motion.div
          className="flex flex-col items-center gap-4 text-center"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1, duration: 0.5 }}
        >
          <Link href="/" className="transition-transform hover:scale-105">
            <Logo />
          </Link>
          <div>
            <h1
              className="text-3xl font-bold text-[#e8dff5] mt-2"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Welcome Back
            </h1>
            <p className="text-sm text-[#6b5a80] mt-2">Sign in to your security dashboard</p>
          </div>
        </motion.div>

        {/* Form card */}
        <motion.form
          onSubmit={handleSubmit}
          className="p-8 space-y-6 rounded-2xl relative overflow-hidden"
          style={{
            background: 'rgba(18, 10, 36, 0.7)',
            border: '1px solid rgba(147,51,234,0.15)',
            boxShadow: '0 0 40px rgba(147,51,234,0.06), 0 20px 60px rgba(0,0,0,0.3)',
            backdropFilter: 'blur(16px)',
          }}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          {/* Top accent */}
          <div
            className="absolute top-0 left-0 right-0 h-[2px]"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.5), transparent)' }}
          />

          {/* Corner glow */}
          <div
            className="absolute top-0 left-0 w-40 h-40 pointer-events-none"
            style={{ background: 'radial-gradient(circle at 0% 0%, rgba(147,51,234,0.06), transparent 70%)' }}
          />

          {/* Error */}
          {error && (
            <motion.div
              className="px-4 py-3 rounded-xl bg-[rgba(255,59,92,0.08)] border border-[rgba(255,59,92,0.2)] text-sm text-[#ff3b5c]"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
            >
              {error}
            </motion.div>
          )}

          {/* Email */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-[#c4b5d9] uppercase tracking-wider">
              Email
            </label>
            <div className="relative">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onFocus={() => setFocused('email')}
                onBlur={() => setFocused(null)}
                placeholder="you@company.com"
                className="w-full rounded-xl px-4 py-3 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none transition-all duration-300"
                style={{
                  fontFamily: "'IBM Plex Sans', sans-serif",
                  background: 'rgba(10, 6, 18, 0.8)',
                  border: `1.5px solid ${focused === 'email' ? 'rgba(147,51,234,0.5)' : 'rgba(147,51,234,0.12)'}`,
                  boxShadow: focused === 'email' ? '0 0 20px rgba(147,51,234,0.1), inset 0 0 20px rgba(147,51,234,0.03)' : 'none',
                }}
              />
            </div>
          </div>

          {/* Password */}
          <div className="space-y-2">
            <label className="block text-xs font-semibold text-[#c4b5d9] uppercase tracking-wider">
              Password
            </label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onFocus={() => setFocused('password')}
                onBlur={() => setFocused(null)}
                placeholder="••••••••"
                className="w-full rounded-xl px-4 py-3 pr-11 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none transition-all duration-300"
                style={{
                  fontFamily: "'IBM Plex Sans', sans-serif",
                  background: 'rgba(10, 6, 18, 0.8)',
                  border: `1.5px solid ${focused === 'password' ? 'rgba(147,51,234,0.5)' : 'rgba(147,51,234,0.12)'}`,
                  boxShadow: focused === 'password' ? '0 0 20px rgba(147,51,234,0.1), inset 0 0 20px rgba(147,51,234,0.03)' : 'none',
                }}
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-lg text-[#6b5a80] hover:text-[#9333ea] hover:bg-[rgba(147,51,234,0.08)] transition-all"
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Submit */}
          <motion.div
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.98 }}
          >
            <Button
              type="submit"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={loading}
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-[#0a0612] border-t-transparent rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Sign In
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              )}
            </Button>
          </motion.div>

          {/* Secure notice */}
          <div className="flex items-center justify-center gap-2 pt-1">
            <Lock className="w-3 h-3 text-[#00e676]" />
            <span className="text-[10px] text-[#6b5a80]">Secured with TLS 1.3 · AES-256-GCM encryption</span>
          </div>
        </motion.form>

        {/* Links */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
        >
          <p className="text-center text-sm text-[#6b5a80]">
            Don&apos;t have an account?{' '}
            <Link href="/register" className="text-[#9333ea] font-medium hover:text-[#a855f7] transition-colors">
              Claim your spot
            </Link>
          </p>
          <p className="text-center">
            <Link href="/" className="text-xs text-[#6b5a80] hover:text-[#c4b5d9] transition-colors">
              ← Back to home
            </Link>
          </p>
        </motion.div>
      </motion.div>
    </div>
  )
}

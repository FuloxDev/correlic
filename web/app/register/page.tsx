'use client'

import { useState, useEffect, Suspense } from 'react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { Shield, ArrowRight, Check, Lock, X } from 'lucide-react'
import { Logo } from '@/components/ui/Logo'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

const perks = [
  'See every file read, network call, and command your AI agent makes',
  '13 threat detection rules + 11 multi-step attack patterns',
  'AI-powered incident investigation — ask questions in plain English',
  'Works with Cursor, Claude Code, Copilot, and any AI agent',
  'Early adopter pricing — lock in your rate',
]

/* ─── Animated side border ─────────────────────────────────────────────────── */

function SideBorder({ side }: { side: 'left' | 'right' }) {
  return (
    <div
      className={`fixed ${side}-0 top-0 bottom-0 w-16 xl:w-20 hidden lg:flex flex-col items-center justify-center gap-0 pointer-events-none z-10`}
    >
      <div
        className="absolute inset-y-0 w-[1px]"
        style={{
          left: side === 'left' ? '50%' : undefined,
          right: side === 'right' ? '50%' : undefined,
          background: 'linear-gradient(180deg, transparent 5%, rgba(147,51,234,0.2) 30%, rgba(147,51,234,0.35) 50%, rgba(147,51,234,0.2) 70%, transparent 95%)',
          boxShadow: '0 0 8px rgba(147,51,234,0.15)',
        }}
      />
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
          top: '10%', left: '-10%',
        }}
        animate={{ x: [0, 40, 0], y: [0, 30, 0] }}
        transition={{ duration: 12, repeat: Infinity, ease: 'easeInOut' }}
      />
      <motion.div
        className="absolute w-[400px] h-[400px] rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 70%)',
          bottom: '5%', right: '-5%',
        }}
        animate={{ x: [0, -30, 0], y: [0, -20, 0] }}
        transition={{ duration: 10, repeat: Infinity, ease: 'easeInOut', delay: 2 }}
      />
      <motion.div
        className="absolute w-[300px] h-[300px] rounded-full"
        style={{
          background: 'radial-gradient(circle, rgba(0,230,118,0.03) 0%, transparent 70%)',
          top: '50%', left: '30%',
        }}
        animate={{ x: [0, 20, 0], y: [0, -25, 0] }}
        transition={{ duration: 14, repeat: Infinity, ease: 'easeInOut', delay: 4 }}
      />
    </div>
  )
}

/* ─── Input component ──────────────────────────────────────────────────────── */

function Input({ label, ...props }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  const [focused, setFocused] = useState(false)
  return (
    <div className="space-y-2">
      <label className="block text-xs font-semibold text-[#c4b5d9] uppercase tracking-wider">{label}</label>
      <input
        {...props}
        onFocus={(e) => { setFocused(true); props.onFocus?.(e) }}
        onBlur={(e) => { setFocused(false); props.onBlur?.(e) }}
        className="w-full rounded-xl px-4 py-3 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none transition-all duration-300"
        style={{
          fontFamily: "'IBM Plex Sans', sans-serif",
          background: 'rgba(10, 6, 18, 0.8)',
          border: `1.5px solid ${focused ? 'rgba(147,51,234,0.5)' : 'rgba(147,51,234,0.12)'}`,
          boxShadow: focused ? '0 0 20px rgba(147,51,234,0.1), inset 0 0 20px rgba(147,51,234,0.03)' : 'none',
        }}
      />
    </div>
  )
}

/* ─── Main Page ────────────────────────────────────────────────────────────── */

export default function RegisterPage() {
  return (
    <Suspense>
      <RegisterForm />
    </Suspense>
  )
}

const professions = [
  'Software Engineer',
  'Security Engineer',
  'DevOps / SRE',
  'Engineering Manager / CTO',
  'Student / Researcher',
  'Indie Hacker / Solo Builder',
  'Vibe Coder',
  'Other',
]

const popularTools = ['Cursor', 'Claude Code', 'GitHub Copilot', 'Windsurf', 'Cline', 'Aider']

function RegisterForm() {
  const searchParams = useSearchParams()
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [company, setCompany] = useState('')
  const [profession, setProfession] = useState('')
  const [tools, setTools] = useState<string[]>([])
  const [customTool, setCustomTool] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')

  // Pre-fill from pricing page query params
  useEffect(() => {
    const qEmail = searchParams.get('email')
    const qProfession = searchParams.get('profession')
    const qTools = searchParams.get('tools')
    if (qEmail) setEmail(qEmail)
    if (qProfession) setProfession(qProfession)
    if (qTools) {
      const parsed = qTools.split(',').map(t => t.trim()).filter(Boolean)
      setTools(parsed)
    }
  }, [searchParams])

  function toggleTool(tool: string) {
    setTools(prev => prev.includes(tool) ? prev.filter(t => t !== tool) : [...prev, tool])
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    // Combine profession + tools (chips + custom) into useCase for backend (existing field)
    const allTools = [...tools, ...(customTool.trim() ? [customTool.trim()] : [])]
    const useCase = [profession, allTools.join(', ')].filter(Boolean).join(' — ')

    const { data, error: err } = await api<{ accessToken: string }>('/auth/register', {
      method: 'POST',
      body: {
        email,
        password,
        name: `${firstName} ${lastName}`.trim(),
        company: company || undefined,
        useCase: useCase || undefined,
      },
    })

    setLoading(false)

    if (err) {
      setError(err)
      return
    }

    // Store token so /account page works immediately
    if (data?.accessToken) {
      localStorage.setItem('correlic_token', data.accessToken)
    }

    setDone(true)
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4 py-16 relative">
      <FloatingOrbs />
      <SideBorder side="left" />
      <SideBorder side="right" />

      <motion.div
        className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-2 gap-12 lg:gap-16 relative z-10"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
      >
        {/* Left — pitch */}
        <motion.div
          className="space-y-10 flex flex-col justify-center"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1, duration: 0.5 }}
        >
          <Link href="/" className="transition-transform hover:scale-105 inline-block">
            <Logo />
          </Link>

          <div>
            <h1
              className="text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5] leading-[1.15]"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Claim Your Spot
            </h1>
            <p className="mt-4 text-lg text-[#c4b5d9] leading-relaxed">
              Join as a founding member — know exactly what your AI coding agents are doing on your machine.
            </p>
            <div
              className="mt-4 inline-flex items-center gap-2.5 px-4 py-2 rounded-xl text-sm"
              style={{
                background: 'rgba(245,158,11,0.06)',
                border: '1px solid rgba(245,158,11,0.2)',
              }}
            >
              <span className="text-[#f59e0b] font-semibold">Founding Member</span>
              <span className="text-[#c4b5d9]">—</span>
              <span className="text-[#c4b5d9]">Free now. Up to 90% off when paid plans launch.</span>
            </div>
          </div>

          <ul className="space-y-4">
            {perks.map((p, i) => (
              <motion.li
                key={p}
                className="flex items-center gap-4 text-sm text-[#c4b5d9]"
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + i * 0.08 }}
              >
                <span
                  className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                  style={{
                    background: 'rgba(147,51,234,0.1)',
                    border: '1px solid rgba(147,51,234,0.25)',
                    boxShadow: '0 0 10px rgba(147,51,234,0.08)',
                  }}
                >
                  <Check className="w-3.5 h-3.5 text-[#9333ea]" />
                </span>
                <span className="text-base">{p}</span>
              </motion.li>
            ))}
          </ul>

          <div className="space-y-3">
            <p className="text-sm text-[#6b5a80]">
              Already have an account?{' '}
              <Link href="/login" className="text-[#9333ea] font-medium hover:text-[#a855f7] transition-colors">
                Sign in
              </Link>
            </p>
            <p>
              <Link href="/" className="text-xs text-[#6b5a80] hover:text-[#c4b5d9] transition-colors">
                ← Back to home
              </Link>
            </p>
          </div>
        </motion.div>

        {/* Right — form */}
        <motion.div
          className="p-8 lg:p-10 rounded-2xl relative overflow-hidden"
          style={{
            background: 'rgba(18, 10, 36, 0.7)',
            border: '1px solid rgba(147,51,234,0.15)',
            boxShadow: '0 0 40px rgba(147,51,234,0.06), 0 20px 60px rgba(0,0,0,0.3)',
            backdropFilter: 'blur(16px)',
          }}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2, duration: 0.5 }}
        >
          {/* Top accent */}
          <div
            className="absolute top-0 left-0 right-0 h-[2px]"
            style={{ background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.5), transparent)' }}
          />
          {/* Corner glow */}
          <div
            className="absolute top-0 right-0 w-48 h-48 pointer-events-none"
            style={{ background: 'radial-gradient(circle at 100% 0%, rgba(147,51,234,0.06), transparent 70%)' }}
          />

          {done ? (
            <motion.div
              className="h-full flex flex-col items-center justify-center text-center gap-5 py-12"
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.4 }}
            >
              <motion.div
                className="w-16 h-16 rounded-2xl flex items-center justify-center"
                style={{
                  background: 'rgba(0,230,118,0.1)',
                  border: '1.5px solid rgba(0,230,118,0.3)',
                  boxShadow: '0 0 30px rgba(0,230,118,0.15)',
                }}
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
              >
                <Check className="w-7 h-7 text-[#00e676]" />
              </motion.div>
              <h2
                className="text-2xl font-bold text-[#e8dff5]"
                style={{ fontFamily: "'Space Grotesk', sans-serif" }}
              >
                You&apos;re on the list!
              </h2>
              <p className="text-[#c4b5d9] max-w-xs">
                We review every request personally. Expect your API key via email within 24 hours.
              </p>
              <div className="flex flex-col gap-3">
                <Link href="/account">
                  <Button variant="primary" size="lg">Go to your account</Button>
                </Link>
                <Link href="/">
                  <Button variant="outline" size="lg">← Back to home</Button>
                </Link>
              </div>
            </motion.div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5 relative">
              <h2
                className="text-xl sm:text-2xl font-bold text-[#e8dff5] mb-2"
                style={{ fontFamily: "'Space Grotesk', sans-serif" }}
              >
                Request Access
              </h2>

              {error && (
                <motion.div
                  className="px-4 py-3 rounded-xl bg-[rgba(255,59,92,0.08)] border border-[rgba(255,59,92,0.2)] text-sm text-[#ff3b5c]"
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  {error}
                </motion.div>
              )}

              <div className="grid grid-cols-2 gap-4">
                <Input
                  label="First name"
                  required
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  placeholder="Ada"
                />
                <Input
                  label="Last name"
                  required
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  placeholder="Lovelace"
                />
              </div>

              <Input
                label="Work email"
                required
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
              />

              <Input
                label="Company"
                type="text"
                value={company}
                onChange={(e) => setCompany(e.target.value)}
                placeholder="Acme Security Inc."
              />

              <div className="space-y-2">
                <Input
                  label="Password"
                  required
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a strong password"
                />
                {password.length > 0 && (
                  <ul className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    {[
                      { met: password.length >= 8, label: '8+ characters' },
                      { met: /[A-Z]/.test(password), label: 'Uppercase letter' },
                      { met: /[0-9]/.test(password), label: 'Number' },
                      { met: /[^A-Za-z0-9]/.test(password), label: 'Special character' },
                    ].map((req) => (
                      <li key={req.label} className="flex items-center gap-1.5">
                        {req.met ? (
                          <Check className="w-3 h-3 text-[#00e676]" />
                        ) : (
                          <X className="w-3 h-3 text-[#ff3b5c]" />
                        )}
                        <span className={req.met ? 'text-[#00e676]' : 'text-[#6b5a80]'}>
                          {req.label}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Profession dropdown */}
              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#c4b5d9] tracking-wide uppercase">
                  Your role <span className="text-[#ff3b5c]">*</span>
                </label>
                <select
                  required
                  value={profession}
                  onChange={(e) => setProfession(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl text-sm text-[#e8dff5] outline-none transition-all duration-200 appearance-none cursor-pointer"
                  style={{
                    fontFamily: "'IBM Plex Sans', sans-serif",
                    background: 'rgba(10, 6, 18, 0.8)',
                    border: '1.5px solid rgba(147,51,234,0.12)',
                    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b5a80' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`,
                    backgroundRepeat: 'no-repeat',
                    backgroundPosition: 'right 14px center',
                  }}
                >
                  <option value="" disabled className="bg-[#0a0612]">Select your role</option>
                  {professions.map((p) => (
                    <option key={p} value={p} className="bg-[#0a0612]">{p}</option>
                  ))}
                </select>
              </div>

              {/* AI tools chips + custom input */}
              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#c4b5d9] tracking-wide uppercase">
                  AI tools you use
                </label>
                <div className="flex flex-wrap gap-2">
                  {popularTools.map((tool) => (
                    <button
                      key={tool}
                      type="button"
                      onClick={() => toggleTool(tool)}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-200"
                      style={{
                        background: tools.includes(tool) ? 'rgba(147,51,234,0.15)' : 'rgba(10, 6, 18, 0.6)',
                        border: tools.includes(tool) ? '1px solid rgba(147,51,234,0.4)' : '1px solid rgba(147,51,234,0.1)',
                        color: tools.includes(tool) ? '#e8dff5' : '#6b5a80',
                      }}
                    >
                      {tool}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  value={customTool}
                  onChange={(e) => setCustomTool(e.target.value)}
                  placeholder="Add another AI agent (e.g. Replit, v0, Bolt...)"
                  maxLength={60}
                  className="w-full px-4 py-2.5 rounded-xl text-sm text-[#e8dff5] placeholder-[#4a3a60] outline-none transition-all duration-200"
                  style={{
                    fontFamily: "'IBM Plex Sans', sans-serif",
                    background: 'rgba(10, 6, 18, 0.8)',
                    border: '1.5px solid rgba(147,51,234,0.12)',
                  }}
                />
              </div>

              <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }}>
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
                      Submitting…
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Request Access
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  )}
                </Button>
              </motion.div>

              <div className="flex items-center justify-center gap-2 pt-1">
                <Lock className="w-3 h-3 text-[#00e676]" />
                <span className="text-[10px] text-[#6b5a80]">No spam. We&apos;ll only contact you about your access.</span>
              </div>
            </form>
          )}
        </motion.div>
      </motion.div>
    </div>
  )
}

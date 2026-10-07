'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import { Monitor, Shield, Server, Check, ArrowRight, Sparkles, Zap, Lock } from 'lucide-react'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { Button } from '@/components/ui/Button'
import { cn } from '@/lib/utils'
import { api } from '@/lib/api'

type Billing = 'monthly' | 'yearly'

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

interface UserProfile {
  id: string
  status: string
  name: string
  email: string
}

export default function PricingPage() {
  const router = useRouter()
  const [billing, setBilling] = useState<Billing>('monthly')

  // Auth state
  const [loggedIn, setLoggedIn] = useState(false)
  const [user, setUser] = useState<UserProfile | null>(null)
  const [loadingUser, setLoadingUser] = useState(true)

  // Free tier form (for non-logged-in users)
  const [email, setEmail] = useState('')
  const [profession, setProfession] = useState('')
  const [tools, setTools] = useState<string[]>([])
  const [customTool, setCustomTool] = useState('')

  // Claim state (for logged-in waitlist users)
  const [claiming, setClaiming] = useState(false)
  const [claimed, setClaimed] = useState(false)

  useEffect(() => {
    const token = localStorage.getItem('correlic_token')
    if (!token) {
      setLoggedIn(false)
      setLoadingUser(false)
      return
    }
    setLoggedIn(true)
    // Fetch user profile to check status
    api<UserProfile>('/users/me', { token }).then(({ data }) => {
      if (data) setUser(data)
      setLoadingUser(false)
    }).catch(() => setLoadingUser(false))
  }, [])

  function handleFreeClaim(e: React.FormEvent) {
    e.preventDefault()
    const allTools = [...tools, ...(customTool.trim() ? [customTool.trim()] : [])]
    const toolsStr = allTools.join(', ')
    const params = new URLSearchParams()
    if (email) params.set('email', email)
    if (profession) params.set('profession', profession)
    if (toolsStr) params.set('tools', toolsStr)
    router.push(`/register?${params.toString()}`)
  }

  async function handleClaimKey() {
    setClaiming(true)
    // For waitlist users, this is just confirmation — admin still needs to approve
    // The user's registration already put them on the waitlist
    setClaimed(true)
    setClaiming(false)
  }

  function toggleTool(tool: string) {
    setTools(prev => prev.includes(tool) ? prev.filter(t => t !== tool) : [...prev, tool])
  }

  const monthly = { single: 9, team: 24 }
  const yearly = { single: 89, team: 239 }
  const price = billing === 'monthly' ? monthly : yearly
  const suffix = billing === 'monthly' ? '/mo' : '/yr'
  const isActive = user?.status === 'active'

  // Determine what the free card shows
  function renderFreeCardContent() {
    if (loadingUser) {
      return (
        <div className="flex items-center justify-center py-8">
          <div className="w-5 h-5 border-2 border-[#f59e0b] border-t-transparent rounded-full animate-spin" />
        </div>
      )
    }

    // Logged in + active → go to account to get API key
    if (loggedIn && isActive) {
      return (
        <div className="space-y-4 py-2">
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl"
            style={{ background: 'rgba(0,230,118,0.06)', border: '1px solid rgba(0,230,118,0.15)' }}>
            <Check className="w-4 h-4 text-[#00e676] shrink-0" />
            <span className="text-sm text-[#c4b5d9]">Your account is approved!</span>
          </div>
          <Button variant="primary" size="lg" className="w-full" onClick={() => router.push('/account')}>
            <span className="flex items-center gap-2">
              Get Your API Key
              <ArrowRight className="w-3.5 h-3.5" />
            </span>
          </Button>
        </div>
      )
    }

    // Logged in + waitlist → show claim button
    if (loggedIn && !isActive) {
      if (claimed) {
        return (
          <motion.div
            className="text-center space-y-3 py-4"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
          >
            <div className="w-12 h-12 rounded-xl flex items-center justify-center mx-auto"
              style={{ background: 'rgba(0,230,118,0.1)', border: '1px solid rgba(0,230,118,0.25)' }}>
              <Check className="w-6 h-6 text-[#00e676]" />
            </div>
            <p className="text-sm font-medium text-[#e8dff5]">You&apos;re on the list!</p>
            <p className="text-xs text-[#6b5a80]">
              We review every request personally. Expect your API key via email within 24 hours.
              You can also check your status on your account page.
            </p>
            <Button variant="outline" onClick={() => router.push('/account')}>
              Check Your Account →
            </Button>
          </motion.div>
        )
      }

      return (
        <div className="space-y-4">
          <div className="flex items-center gap-3 px-4 py-3 rounded-xl"
            style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.12)' }}>
            <Sparkles className="w-4 h-4 text-[#f59e0b] shrink-0" />
            <span className="text-sm text-[#c4b5d9]">
              Signed in as <span className="text-[#e8dff5] font-medium">{user?.email}</span>
            </span>
          </div>
          <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }}>
            <Button
              type="button"
              variant="primary"
              size="lg"
              className="w-full"
              disabled={claiming}
              onClick={handleClaimKey}
            >
              <span className="flex items-center gap-2">
                <Shield className="w-4 h-4" />
                {claiming ? 'Claiming...' : 'Claim Your Free API Key'}
                <ArrowRight className="w-3.5 h-3.5" />
              </span>
            </Button>
          </motion.div>
          <p className="text-[10px] text-[#6b5a80] text-center">
            We&apos;ll review your request and send the API key to your email within 24 hours.
          </p>
        </div>
      )
    }

    // Not logged in → show profession/tools form → redirect to register
    return (
      <form onSubmit={handleFreeClaim} className="space-y-3">
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          className="w-full px-3.5 py-2 rounded-lg text-sm text-[#e8dff5] placeholder-[#4a3a60] outline-none transition-all duration-200 focus:ring-1 focus:ring-[#f59e0b]/30"
          style={{ background: 'rgba(10, 6, 18, 0.6)', border: '1px solid rgba(147,51,234,0.1)' }}
        />

        <select
          required
          value={profession}
          onChange={(e) => setProfession(e.target.value)}
          className="w-full px-3.5 py-2 rounded-lg text-sm text-[#e8dff5] outline-none transition-all duration-200 appearance-none cursor-pointer focus:ring-1 focus:ring-[#f59e0b]/30"
          style={{
            background: 'rgba(10, 6, 18, 0.6)',
            border: '1px solid rgba(147,51,234,0.1)',
            backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b5a80' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`,
            backgroundRepeat: 'no-repeat',
            backgroundPosition: 'right 12px center',
          }}
        >
          <option value="" disabled className="bg-[#0a0612]">Your role</option>
          {professions.map((p) => (
            <option key={p} value={p} className="bg-[#0a0612]">{p}</option>
          ))}
        </select>

        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5">
            {popularTools.map((tool) => (
              <button
                key={tool}
                type="button"
                onClick={() => toggleTool(tool)}
                className={cn(
                  'px-2.5 py-1 rounded-md text-[11px] font-medium transition-all duration-200',
                  tools.includes(tool) ? 'text-[#e8dff5]' : 'text-[#6b5a80] hover:text-[#c4b5d9]'
                )}
                style={{
                  background: tools.includes(tool) ? 'rgba(245,158,11,0.12)' : 'rgba(10, 6, 18, 0.4)',
                  border: tools.includes(tool) ? '1px solid rgba(245,158,11,0.25)' : '1px solid rgba(147,51,234,0.08)',
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
            placeholder="Other AI agent..."
            maxLength={60}
            className="w-full px-3.5 py-2 rounded-lg text-xs text-[#e8dff5] placeholder-[#4a3a60] outline-none transition-all duration-200 focus:ring-1 focus:ring-[#f59e0b]/30"
            style={{ background: 'rgba(10, 6, 18, 0.6)', border: '1px solid rgba(147,51,234,0.1)' }}
          />
        </div>

        <motion.div whileHover={{ scale: 1.01 }} whileTap={{ scale: 0.98 }}>
          <Button type="submit" variant="primary" size="lg" className="w-full">
            <span className="flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Register &amp; Claim
              <ArrowRight className="w-3.5 h-3.5" />
            </span>
          </Button>
        </motion.div>

        <p className="text-[10px] text-[#6b5a80] text-center">
          Already registered?{' '}
          <button type="button" onClick={() => router.push('/login')} className="text-[#9333ea] hover:text-[#a855f7] transition-colors">
            Sign in
          </button>
        </p>
      </form>
    )
  }

  return (
    <>
      <Navbar />
      <main className="pt-28 pb-24 min-h-screen relative">
        {/* Background */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: 'radial-gradient(ellipse 60% 40% at 50% 20%, rgba(147,51,234,0.06) 0%, transparent 70%)',
        }} />

        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 relative space-y-16">

          {/* ── Header ── */}
          <motion.div
            className="text-center space-y-5"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <motion.span
              className="inline-block text-xs font-semibold text-[#9333ea] uppercase tracking-widest px-4 py-1.5 rounded-full"
              style={{ background: 'rgba(147,51,234,0.08)', border: '1px solid rgba(147,51,234,0.2)' }}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
            >
              Pricing
            </motion.span>
            <h1
              className="text-4xl sm:text-5xl lg:text-6xl font-bold text-[#e8dff5] leading-tight"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Know What Your AI Does.<br />
              <span className="text-[#9333ea]">Pay What Feels Right.</span>
            </h1>
            <p className="text-lg text-[#c4b5d9] max-w-2xl mx-auto leading-relaxed">
              Founding members get full access for free. No credit card. No catch.<br />
              Just tell us what you build with AI.
            </p>
          </motion.div>

          {/* ── Billing Toggle ── */}
          <motion.div
            className="flex justify-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.1 }}
          >
            <div
              className="inline-flex items-center rounded-full p-1 gap-1"
              style={{ background: 'rgba(10, 6, 18, 0.8)', border: '1px solid rgba(147,51,234,0.15)' }}
            >
              {(['monthly', 'yearly'] as const).map((b) => (
                <button
                  key={b}
                  onClick={() => setBilling(b)}
                  className={cn(
                    'px-6 py-2.5 rounded-full text-sm font-semibold transition-all duration-300',
                    billing === b ? 'text-[#e8dff5]' : 'text-[#6b5a80] hover:text-[#c4b5d9]'
                  )}
                  style={{
                    background: billing === b ? 'rgba(147,51,234,0.12)' : 'transparent',
                    boxShadow: billing === b ? '0 0 20px rgba(147,51,234,0.1)' : 'none',
                    border: billing === b ? '1px solid rgba(147,51,234,0.3)' : '1px solid transparent',
                  }}
                >
                  {b === 'monthly' ? 'Monthly' : 'Yearly'}
                </button>
              ))}
              <AnimatePresence>
                {billing === 'yearly' && (
                  <motion.span
                    className="mr-2 ml-1 text-[10px] font-bold px-2.5 py-1 rounded-full whitespace-nowrap"
                    style={{ background: 'rgba(0,230,118,0.12)', color: '#00e676', border: '1px solid rgba(0,230,118,0.25)' }}
                    initial={{ opacity: 0, width: 0, marginLeft: 0, marginRight: 0, paddingLeft: 0, paddingRight: 0 }}
                    animate={{ opacity: 1, width: 'auto', marginLeft: 4, marginRight: 8, paddingLeft: 10, paddingRight: 10 }}
                    exit={{ opacity: 0, width: 0, marginLeft: 0, marginRight: 0, paddingLeft: 0, paddingRight: 0 }}
                  >
                    Save ~17%
                  </motion.span>
                )}
              </AnimatePresence>
            </div>
          </motion.div>

          {/* ── Cards ── */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 lg:gap-6 items-start">

            {/* ─── 1 Device (DISABLED) ─── */}
            <motion.div
              className="rounded-2xl p-7 flex flex-col relative overflow-hidden order-2 lg:order-1 opacity-50 pointer-events-none select-none"
              style={{
                background: 'rgba(18, 10, 36, 0.4)',
                border: '1px solid rgba(147,51,234,0.08)',
                backdropFilter: 'blur(12px)',
              }}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 0.5, y: 0 }}
              transition={{ delay: 0.15 }}
            >
              <div className="space-y-5 flex-1">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                    style={{ background: 'rgba(147,51,234,0.08)', border: '1px solid rgba(147,51,234,0.12)' }}>
                    <Monitor className="w-4.5 h-4.5 text-[#6b5a80]" />
                  </div>
                  <span className="text-sm font-semibold text-[#6b5a80] uppercase tracking-wider">1 Device</span>
                </div>

                <div>
                  <div className="flex items-baseline gap-1.5">
                    <AnimatePresence mode="wait">
                      <motion.span
                        key={billing}
                        className="text-5xl font-bold text-[#6b5a80]"
                        style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                        initial={{ opacity: 0, y: -8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 8 }}
                        transition={{ duration: 0.15 }}
                      >
                        ${price.single}
                      </motion.span>
                    </AnimatePresence>
                    <span className="text-sm text-[#4a3a60]">{suffix}</span>
                  </div>
                  {billing === 'yearly' && (
                    <p className="text-xs text-[#4a3a60] mt-1">${(yearly.single / 12).toFixed(2)}/mo billed annually</p>
                  )}
                </div>

                <div className="h-px" style={{ background: 'rgba(147,51,234,0.06)' }} />

                <ul className="space-y-3">
                  {[
                    'Kernel-level monitoring',
                    '13 detection rules',
                    'Real-time dashboard',
                    '7-day retention',
                    'Email alerts',
                  ].map((f) => (
                    <li key={f} className="flex items-center gap-2.5 text-sm text-[#4a3a60]">
                      <Check className="w-3.5 h-3.5 text-[#4a3a60] shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-6">
                <div className="w-full py-3 rounded-xl text-center text-sm font-semibold text-[#6b5a80] flex items-center justify-center gap-2"
                  style={{ background: 'rgba(10,6,18,0.5)', border: '1px solid rgba(147,51,234,0.08)' }}>
                  <Lock className="w-3.5 h-3.5" />
                  Coming Soon
                </div>
              </div>
            </motion.div>

            {/* ─── Free — FEATURED ─── */}
            <motion.div
              data-free-card
              className="rounded-2xl relative overflow-hidden flex flex-col order-1 lg:order-2"
              style={{
                background: 'rgba(18, 10, 36, 0.9)',
                border: '1.5px solid rgba(245,158,11,0.25)',
                boxShadow: '0 0 60px rgba(245,158,11,0.06), 0 4px 80px rgba(0,0,0,0.4)',
                backdropFilter: 'blur(16px)',
              }}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              {/* Top glow bar */}
              <div className="absolute top-0 left-0 right-0 h-[2px]"
                style={{ background: 'linear-gradient(90deg, transparent 10%, #f59e0b 50%, transparent 90%)' }} />
              {/* Corner glows */}
              <div className="absolute top-0 right-0 w-64 h-64 pointer-events-none"
                style={{ background: 'radial-gradient(circle at 100% 0%, rgba(245,158,11,0.05), transparent 60%)' }} />
              <div className="absolute bottom-0 left-0 w-48 h-48 pointer-events-none"
                style={{ background: 'radial-gradient(circle at 0% 100%, rgba(147,51,234,0.04), transparent 60%)' }} />

              {/* Badge ribbon */}
              <div className="flex justify-center pt-4 pb-1">
                <span className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-bold"
                  style={{ background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.2)' }}>
                  <Sparkles className="w-3 h-3" />
                  Founding Member — Limited
                </span>
              </div>

              <div className="p-7 flex flex-col flex-1">
                <div className="space-y-4 flex-1">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                      style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.2)' }}>
                      <Shield className="w-4.5 h-4.5 text-[#f59e0b]" />
                    </div>
                    <span className="text-sm font-semibold text-[#f59e0b] uppercase tracking-wider">Free Access</span>
                  </div>

                  <div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-5xl font-bold text-[#e8dff5]" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>$0</span>
                      <span className="text-sm text-[#6b5a80]">forever</span>
                    </div>
                    <p className="text-xs text-[#f59e0b] mt-1.5 font-medium">Lock in founding member pricing for life</p>
                  </div>

                  <div className="h-px" style={{ background: 'rgba(245,158,11,0.1)' }} />

                  <ul className="space-y-2.5">
                    {[
                      'Everything in paid plans',
                      '1 device · 7-day retention',
                      'AI-powered investigation',
                      'Pricing locked — never increases',
                    ].map((f) => (
                      <li key={f} className="flex items-center gap-2.5 text-sm text-[#c4b5d9]">
                        <Check className="w-3.5 h-3.5 text-[#f59e0b] shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>

                  <div className="h-px" style={{ background: 'rgba(245,158,11,0.1)' }} />

                  {/* Dynamic content based on auth state */}
                  {renderFreeCardContent()}
                </div>
              </div>
            </motion.div>

            {/* ─── 3 Devices (DISABLED) ─── */}
            <motion.div
              className="rounded-2xl p-7 flex flex-col relative overflow-hidden order-3 opacity-50 pointer-events-none select-none"
              style={{
                background: 'rgba(18, 10, 36, 0.4)',
                border: '1px solid rgba(147,51,234,0.08)',
                backdropFilter: 'blur(12px)',
              }}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 0.5, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="space-y-5 flex-1">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                      style={{ background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.12)' }}>
                      <Server className="w-4.5 h-4.5 text-[#6b5a80]" />
                    </div>
                    <span className="text-sm font-semibold text-[#6b5a80] uppercase tracking-wider">3 Devices</span>
                  </div>
                  <span className="text-[10px] font-bold px-2.5 py-1 rounded-full"
                    style={{ background: 'rgba(147,51,234,0.06)', color: '#6b5a80', border: '1px solid rgba(147,51,234,0.1)' }}>
                    Best Value
                  </span>
                </div>

                <div>
                  <div className="flex items-baseline gap-1.5">
                    <AnimatePresence mode="wait">
                      <motion.span
                        key={billing}
                        className="text-5xl font-bold text-[#6b5a80]"
                        style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                        initial={{ opacity: 0, y: -8 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 8 }}
                        transition={{ duration: 0.15 }}
                      >
                        ${price.team}
                      </motion.span>
                    </AnimatePresence>
                    <span className="text-sm text-[#4a3a60]">{suffix}</span>
                  </div>
                  <p className="text-xs text-[#4a3a60] mt-1">
                    {billing === 'monthly'
                      ? `$${(monthly.team / 3).toFixed(0)}/device/mo`
                      : `$${(yearly.team / 12).toFixed(2)}/mo billed annually`}
                  </p>
                </div>

                <div className="h-px" style={{ background: 'rgba(147,51,234,0.06)' }} />

                <ul className="space-y-3">
                  {[
                    'Everything in 1 Device',
                    '3 devices included',
                    '30-day retention',
                    'Priority support',
                    'Team dashboard (coming soon)',
                  ].map((f) => (
                    <li key={f} className="flex items-center gap-2.5 text-sm text-[#4a3a60]">
                      <Check className="w-3.5 h-3.5 text-[#4a3a60] shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-6">
                <div className="w-full py-3 rounded-xl text-center text-sm font-semibold text-[#6b5a80] flex items-center justify-center gap-2"
                  style={{ background: 'rgba(10,6,18,0.5)', border: '1px solid rgba(147,51,234,0.08)' }}>
                  <Lock className="w-3.5 h-3.5" />
                  Coming Soon
                </div>
              </div>
            </motion.div>
          </div>

          {/* ── Vibe Coder callout ── */}
          <motion.div
            className="rounded-2xl p-8 text-center relative overflow-hidden"
            style={{
              background: 'rgba(18, 10, 36, 0.5)',
              border: '1px solid rgba(0,230,118,0.12)',
            }}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25 }}
          >
            <div className="absolute top-0 left-0 right-0 h-[1px]"
              style={{ background: 'linear-gradient(90deg, transparent, rgba(0,230,118,0.3), transparent)' }} />
            <div className="max-w-2xl mx-auto space-y-4">
              <div className="flex justify-center">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                  style={{ background: 'rgba(0,230,118,0.08)', border: '1px solid rgba(0,230,118,0.15)' }}>
                  <Zap className="w-5 h-5 text-[#00e676]" />
                </div>
              </div>
              <h3 className="text-xl font-bold text-[#e8dff5]" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
                Vibe coder? No problem.
              </h3>
              <p className="text-[#c4b5d9] leading-relaxed">
                Not a &ldquo;real developer&rdquo;? We don&apos;t care. If you use AI to build things — you belong here.
                Correlic was built for anyone who lets AI touch their machine. Whether you&apos;re shipping
                your first side project or you&apos;ve been coding for 20 years, you deserve to know what
                your AI agent is actually doing. New minds are exactly what this space needs.
              </p>
              <Button variant="outline" onClick={() => {
                const el = document.querySelector('[data-free-card]')
                el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
              }}>
                Claim Your Free Access →
              </Button>
            </div>
          </motion.div>

          {/* ── Trust footer ── */}
          <motion.div
            className="grid grid-cols-2 sm:grid-cols-4 gap-6"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
          >
            {[
              { label: 'Self-hosted', desc: 'Your data stays on your machine' },
              { label: 'No credit card', desc: 'Free tier requires zero payment info' },
              { label: 'Cancel anytime', desc: 'No lock-in, no contracts' },
              { label: 'All AI agents', desc: 'Cursor, Claude Code, Copilot & more' },
            ].map((item) => (
              <div key={item.label} className="text-center space-y-1">
                <p className="text-sm font-semibold text-[#e8dff5]">{item.label}</p>
                <p className="text-xs text-[#6b5a80]">{item.desc}</p>
              </div>
            ))}
          </motion.div>

        </div>
      </main>
      <Footer />
    </>
  )
}

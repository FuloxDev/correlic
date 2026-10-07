'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  User, Mail, Building2, Briefcase, Calendar, Shield,
  Key, Check, Clock, Crown, Download, MessageSquare,
  ExternalLink, BookOpen, Terminal, Eye, Sparkles, LogOut,
  Copy, RefreshCw, AlertTriangle,
} from 'lucide-react'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

interface UserProfile {
  id: string
  email: string
  name: string
  company: string | null
  useCase: string | null
  role: string
  status: string
  createdAt: string
}

interface ApiKey {
  id: string
  keyPrefix: string
  name: string
  lastUsedAt: string | null
  revokedAt: string | null
  expiresAt: string | null
  createdAt: string
}

const gettingStartedSteps = [
  {
    id: 'install',
    icon: Download,
    title: 'Install the agent',
    description: 'One command installs the Correlic agent on your machine. Takes about 30 seconds.',
    link: '/download',
    linkLabel: 'Go to download page',
  },
  {
    id: 'configure',
    icon: Terminal,
    title: 'Paste your API key',
    description: 'The installer will prompt for your API key. Copy it from this page and paste it when asked.',
    link: null,
    linkLabel: null,
  },
  {
    id: 'use',
    icon: Eye,
    title: 'Use your AI tools normally',
    description: 'Open Cursor, Claude Code, or Copilot and work as usual. Correlic monitors silently in the background.',
    link: null,
    linkLabel: null,
  },
  {
    id: 'dashboard',
    icon: Sparkles,
    title: 'Open your dashboard',
    description: 'Visit localhost:3001 to see every file read, network call, and command your AI agent made.',
    link: null,
    linkLabel: null,
  },
]

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  })
}

function daysUntil(iso: string) {
  const diff = new Date(iso).getTime() - Date.now()
  return Math.max(0, Math.ceil(diff / 86_400_000))
}

export default function AccountPage() {
  const router = useRouter()
  const [user, setUser] = useState<UserProfile | null>(null)
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)
  const [completedSteps, setCompletedSteps] = useState<string[]>([])
  const [regeneratedKey, setRegeneratedKey] = useState<string | null>(null)
  const [regenerating, setRegenerating] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)
  const [showRegenerateConfirm, setShowRegenerateConfirm] = useState(false)
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('correlic_token')
    if (!token) {
      router.push('/login')
      return
    }

    // Load completed steps from localStorage
    const saved = localStorage.getItem('correlic_checklist')
    if (saved) setCompletedSteps(JSON.parse(saved))

    async function load() {
      const [profileRes, keysRes] = await Promise.all([
        api<UserProfile>('/users/me', { token: token! }),
        api<{ keys: ApiKey[] }>('/keys', { token: token! }),
      ])

      if (profileRes.error || !profileRes.data) {
        localStorage.removeItem('correlic_token')
        router.push('/login')
        return
      }

      setUser(profileRes.data)
      if (keysRes.data) setKeys(keysRes.data.keys)
      setLoading(false)
    }

    load()
  }, [router])

  function toggleStep(id: string) {
    const next = completedSteps.includes(id)
      ? completedSteps.filter((s) => s !== id)
      : [...completedSteps, id]
    setCompletedSteps(next)
    localStorage.setItem('correlic_checklist', JSON.stringify(next))
  }

  function showToast(message: string, type: 'success' | 'error') {
    setToast({ message, type })
    setTimeout(() => setToast(null), 5000)
  }

  async function handleRegenerate() {
    const token = localStorage.getItem('correlic_token')
    if (!token) return
    setRegenerating(true)
    setShowRegenerateConfirm(false)
    const res = await api<{ apiKey: string; keys: ApiKey[] }>('/keys/regenerate', { method: 'POST', token })
    if (res.data?.apiKey) {
      setRegeneratedKey(res.data.apiKey)
      if (res.data.keys) setKeys(res.data.keys)
      showToast('API key regenerated successfully. Copy it now — it won\u2019t be shown again.', 'success')
    } else {
      showToast(res.error || 'Failed to regenerate API key. Please try again.', 'error')
    }
    setRegenerating(false)
  }

  function copyFullKey() {
    if (!regeneratedKey) return
    navigator.clipboard.writeText(regeneratedKey)
    setCopiedKey(true)
    showToast('API key copied to clipboard.', 'success')
    setTimeout(() => setCopiedKey(false), 2000)
  }

  function logout() {
    localStorage.removeItem('correlic_token')
    localStorage.removeItem('correlic_checklist')
    router.push('/')
  }

  if (loading) {
    return (
      <>
        <Navbar />
        <main className="min-h-screen pt-32 flex items-center justify-center">
          <div className="flex items-center gap-3 text-[#6b5a80]">
            <span className="w-5 h-5 border-2 border-[#9333ea] border-t-transparent rounded-full animate-spin" />
            Loading your account...
          </div>
        </main>
      </>
    )
  }

  if (!user) return null

  const isActive = user.status === 'active'
  const activeKeys = keys.filter((k) => !k.revokedAt)
  return (
    <>
      <Navbar />
      <main className="min-h-screen pt-32 pb-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">

          {/* Header */}
          <motion.div
            className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-10"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div>
              <div className="flex items-center gap-3">
                <h1
                  className="text-2xl sm:text-3xl font-bold text-[#e8dff5]"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  Welcome back, {user.name.split(' ')[0]}
                </h1>
                {/* Founding Member badge */}
                <div
                  className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold"
                  style={{
                    background: 'rgba(245,158,11,0.08)',
                    border: '1px solid rgba(245,158,11,0.25)',
                    color: '#f59e0b',
                  }}
                >
                  <Crown className="w-3 h-3" />
                  Founding Member
                </div>
              </div>
              <p className="mt-1 text-sm text-[#6b5a80]">
                {isActive ? 'Your account is active' : 'Your request is being reviewed'}
              </p>
            </div>
            <button
              onClick={logout}
              className="flex items-center gap-2 text-sm text-[#6b5a80] hover:text-[#c4b5d9] transition-colors self-start"
            >
              <LogOut className="w-4 h-4" />
              Sign out
            </button>
          </motion.div>

          {/* Status Banner — Waitlist */}
          {!isActive && (
            <motion.div
              className="mb-8 p-6 rounded-xl relative overflow-hidden"
              style={{
                background: 'rgba(245,158,11,0.04)',
                border: '1px solid rgba(245,158,11,0.15)',
              }}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <div
                className="absolute top-0 left-0 right-0 h-[2px]"
                style={{ background: 'linear-gradient(90deg, transparent, rgba(245,158,11,0.5), transparent)' }}
              />
              <div className="flex items-start gap-4">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                  style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.2)' }}
                >
                  <Clock className="w-5 h-5 text-[#f59e0b]" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-[#e8dff5]" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
                    Your request is being reviewed
                  </h3>
                  <p className="mt-1 text-sm text-[#c4b5d9]">
                    We review every request personally. You registered on {formatDate(user.createdAt)} — you&apos;ll be approved within 24 hours. Once approved, you can generate your API key from this page.
                  </p>
                  <p className="mt-3 text-xs text-[#6b5a80]">
                    While you wait — follow us on{' '}
                    <a href="https://x.com/correlic" target="_blank" rel="noopener noreferrer" className="text-[#9333ea] hover:text-[#a855f7]">
                      Twitter/X
                    </a>
                    {' '}for updates, or{' '}
                    <Link href="/posts" className="text-[#9333ea] hover:text-[#a855f7]">
                      read our latest posts
                    </Link>.
                  </p>
                </div>
              </div>
            </motion.div>
          )}

          {/* Active status banner */}
          {isActive && (
            <motion.div
              className="mb-8 p-5 rounded-xl flex items-center gap-3"
              style={{
                background: 'rgba(0,230,118,0.04)',
                border: '1px solid rgba(0,230,118,0.15)',
              }}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              <span
                className="w-2 h-2 rounded-full bg-[#00e676] shrink-0"
                style={{ boxShadow: '0 0 8px rgba(0,230,118,0.5)' }}
              />
              <span className="text-sm text-[#c4b5d9]">
                Your account is active. You have full access to Correlic.
              </span>
            </motion.div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* ── Left Column: Profile + API Keys ── */}
            <div className="lg:col-span-2 space-y-6">

              {/* Profile Card */}
              <motion.div
                className="p-6 rounded-xl relative overflow-hidden"
                style={{
                  background: 'rgba(18, 10, 36, 0.7)',
                  border: '1px solid rgba(147,51,234,0.15)',
                  backdropFilter: 'blur(12px)',
                }}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 }}
              >
                <div
                  className="absolute top-0 left-0 right-0 h-[2px]"
                  style={{ background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.4), transparent)' }}
                />
                <h2
                  className="text-lg font-semibold text-[#e8dff5] mb-5"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  Profile
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  {[
                    { icon: User, label: 'Name', value: user.name },
                    { icon: Mail, label: 'Email', value: user.email },
                    { icon: Building2, label: 'Company', value: user.company || '—' },
                    { icon: Briefcase, label: 'Use Case', value: user.useCase || '—' },
                    { icon: Calendar, label: 'Member Since', value: formatDate(user.createdAt) },
                    { icon: Shield, label: 'Status', value: user.status.charAt(0).toUpperCase() + user.status.slice(1) },
                  ].map((field) => (
                    <div key={field.label} className="flex items-start gap-3">
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                        style={{ background: 'rgba(147,51,234,0.08)', border: '1px solid rgba(147,51,234,0.15)' }}
                      >
                        <field.icon className="w-4 h-4 text-[#9333ea]" />
                      </div>
                      <div>
                        <div className="text-xs text-[#6b5a80] uppercase tracking-wider">{field.label}</div>
                        <div className="text-sm text-[#e8dff5] mt-0.5">{field.value}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>

              {/* API Keys Card — only for active users */}
              {isActive && (
                <motion.div
                  className="p-6 rounded-xl relative overflow-hidden"
                  style={{
                    background: 'rgba(18, 10, 36, 0.7)',
                    border: '1px solid rgba(147,51,234,0.15)',
                    backdropFilter: 'blur(12px)',
                  }}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 }}
                >
                  <div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    style={{ background: 'linear-gradient(90deg, transparent, rgba(0,230,118,0.3), transparent)' }}
                  />
                  <div className="flex items-center justify-between mb-5">
                    <h2
                      className="text-lg font-semibold text-[#e8dff5]"
                      style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                    >
                      API Keys
                    </h2>
                    <span className="text-xs text-[#6b5a80]">
                      {activeKeys.length} active {activeKeys.length === 1 ? 'key' : 'keys'}
                    </span>
                  </div>

                  {/* Regenerated key banner — shown once after regeneration */}
                  {regeneratedKey && (
                    <motion.div
                      className="mb-4 p-4 rounded-xl"
                      style={{
                        background: 'rgba(0,230,118,0.04)',
                        border: '1px solid rgba(0,230,118,0.25)',
                      }}
                      initial={{ opacity: 0, y: -8 }}
                      animate={{ opacity: 1, y: 0 }}
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Check className="w-4 h-4 text-[#00e676]" />
                        <span className="text-sm font-medium text-[#00e676]">New API key generated</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <code
                          className="text-xs text-[#e8dff5] bg-[#0a0612] px-3 py-2 rounded-lg flex-1 break-all select-all"
                          style={{ fontFamily: "'JetBrains Mono', monospace" }}
                        >
                          {regeneratedKey}
                        </code>
                        <button
                          onClick={copyFullKey}
                          className="p-2 rounded-lg text-[#6b5a80] hover:text-[#9333ea] transition-colors shrink-0"
                          style={{ background: 'rgba(147,51,234,0.08)', border: '1px solid rgba(147,51,234,0.15)' }}
                          title="Copy full API key"
                        >
                          {copiedKey
                            ? <Check className="w-4 h-4 text-[#00e676]" />
                            : <Copy className="w-4 h-4" />
                          }
                        </button>
                      </div>
                      <p className="mt-2 text-xs text-[#f59e0b]">
                        Save this key now — it won&apos;t be shown again.
                      </p>
                    </motion.div>
                  )}

                  {activeKeys.length === 0 ? (
                    <p className="text-sm text-[#6b5a80] py-4 text-center">
                      No API keys yet. Click &quot;Regenerate&quot; below to create one.
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {activeKeys.map((k) => (
                        <div
                          key={k.id}
                          className="flex items-center justify-between p-4 rounded-xl transition-all duration-200 group"
                          style={{
                            background: 'rgba(10, 6, 18, 0.6)',
                            border: '1px solid rgba(147,51,234,0.1)',
                          }}
                        >
                          <div className="flex items-center gap-3">
                            <div
                              className="w-8 h-8 rounded-lg flex items-center justify-center"
                              style={{ background: 'rgba(0,230,118,0.08)', border: '1px solid rgba(0,230,118,0.15)' }}
                            >
                              <Key className="w-4 h-4 text-[#00e676]" />
                            </div>
                            <div>
                              <code
                                className="text-sm text-[#e8dff5]"
                                style={{ fontFamily: "'JetBrains Mono', monospace" }}
                              >
                                {k.keyPrefix}••••••••
                              </code>
                              <div className="text-xs text-[#6b5a80] mt-0.5">
                                {k.name} · Created {formatDate(k.createdAt)}
                              </div>
                            </div>
                          </div>
                          <div className="text-right">
                            {k.expiresAt && (
                              <div className="text-xs text-[#6b5a80]">
                                {daysUntil(k.expiresAt) > 0
                                  ? <span>Expires in <span className="text-[#c4b5d9]">{daysUntil(k.expiresAt)}d</span></span>
                                  : <span className="text-[#ff3b5c]">Expired</span>
                                }
                              </div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Regenerate key button + confirmation */}
                  <div className="mt-5">
                    {showRegenerateConfirm ? (
                      <motion.div
                        className="p-4 rounded-xl"
                        style={{
                          background: 'rgba(245,158,11,0.06)',
                          border: '1px solid rgba(245,158,11,0.25)',
                        }}
                        initial={{ opacity: 0, y: 4 }}
                        animate={{ opacity: 1, y: 0 }}
                      >
                        <div className="flex items-start gap-3">
                          <div
                            className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                            style={{ background: 'rgba(245,158,11,0.12)', border: '1px solid rgba(245,158,11,0.25)' }}
                          >
                            <AlertTriangle className="w-4.5 h-4.5 text-[#f59e0b]" />
                          </div>
                          <div className="flex-1">
                            <p className="text-sm font-medium text-[#e8dff5]">Are you sure?</p>
                            <p className="text-xs text-[#c4b5d9] mt-1">
                              This will revoke your current key and generate a new one. Any agents using the old key will stop working.
                            </p>
                            <div className="flex items-center gap-3 mt-3">
                              <button
                                onClick={handleRegenerate}
                                disabled={regenerating}
                                className="px-4 py-2 text-sm font-medium rounded-lg transition-all duration-200 hover:brightness-110"
                                style={{
                                  background: 'rgba(255,59,92,0.15)',
                                  border: '1px solid rgba(255,59,92,0.35)',
                                  color: '#ff3b5c',
                                }}
                              >
                                {regenerating ? 'Generating...' : 'Yes, regenerate key'}
                              </button>
                              <button
                                onClick={() => setShowRegenerateConfirm(false)}
                                className="px-4 py-2 text-sm text-[#6b5a80] hover:text-[#c4b5d9] transition-colors"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    ) : (
                      <button
                        onClick={() => setShowRegenerateConfirm(true)}
                        disabled={regenerating}
                        className="w-full flex items-center justify-center gap-2 px-4 py-3 text-sm font-medium rounded-xl transition-all duration-200 hover:brightness-110"
                        style={{
                          background: 'linear-gradient(135deg, rgba(147,51,234,0.12), rgba(147,51,234,0.06))',
                          border: '1px solid rgba(147,51,234,0.25)',
                          color: '#c4b5d9',
                        }}
                      >
                        <RefreshCw className={`w-4 h-4 ${regenerating ? 'animate-spin' : ''}`} />
                        {activeKeys.length > 0 ? 'Regenerate API Key' : 'Generate API Key'}
                      </button>
                    )}
                  </div>

                  <p className="mt-3 text-xs text-[#6b5a80] text-center">
                    For security, the full key is only shown once after generation.
                  </p>
                </motion.div>
              )}
            </div>

            {/* ── Right Column: Getting Started + Quick Links ── */}
            <div className="space-y-6">

              {/* Getting Started Checklist */}
              {isActive && (
                <motion.div
                  className="p-6 rounded-xl relative overflow-hidden"
                  style={{
                    background: 'rgba(18, 10, 36, 0.7)',
                    border: '1px solid rgba(147,51,234,0.15)',
                    backdropFilter: 'blur(12px)',
                  }}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.25 }}
                >
                  <div
                    className="absolute top-0 left-0 right-0 h-[2px]"
                    style={{ background: 'linear-gradient(90deg, transparent, rgba(245,158,11,0.4), transparent)' }}
                  />
                  <h2
                    className="text-lg font-semibold text-[#e8dff5] mb-5"
                    style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                  >
                    Getting Started
                  </h2>

                  <div className="space-y-3">
                    {gettingStartedSteps.map((step, i) => {
                      const Icon = step.icon
                      const done = completedSteps.includes(step.id)
                      return (
                        <button
                          key={step.id}
                          onClick={() => toggleStep(step.id)}
                          className="w-full text-left flex items-start gap-3 p-3 rounded-lg transition-all duration-200 group"
                          style={{
                            background: done ? 'rgba(0,230,118,0.04)' : 'transparent',
                            border: `1px solid ${done ? 'rgba(0,230,118,0.1)' : 'rgba(147,51,234,0.06)'}`,
                          }}
                        >
                          {/* Checkbox */}
                          <div
                            className="w-6 h-6 rounded-md flex items-center justify-center shrink-0 mt-0.5 transition-all duration-200"
                            style={{
                              background: done ? 'rgba(0,230,118,0.15)' : 'rgba(147,51,234,0.06)',
                              border: `1.5px solid ${done ? 'rgba(0,230,118,0.4)' : 'rgba(147,51,234,0.15)'}`,
                            }}
                          >
                            {done && <Check className="w-3.5 h-3.5 text-[#00e676]" />}
                            {!done && <span className="text-[10px] text-[#6b5a80] font-semibold">{i + 1}</span>}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className={`text-sm font-medium transition-colors ${done ? 'text-[#6b5a80] line-through' : 'text-[#e8dff5]'}`}>
                              {step.title}
                            </div>
                            <div className="text-xs text-[#6b5a80] mt-0.5 leading-relaxed">
                              {step.description}
                            </div>
                            {step.link && !done && (
                              <Link
                                href={step.link}
                                className="inline-flex items-center gap-1 text-xs text-[#9333ea] hover:text-[#a855f7] mt-1.5 transition-colors"
                                onClick={(e) => e.stopPropagation()}
                              >
                                {step.linkLabel} <ExternalLink className="w-3 h-3" />
                              </Link>
                            )}
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </motion.div>
              )}

              {/* Quick Links */}
              <motion.div
                className="p-6 rounded-xl relative overflow-hidden"
                style={{
                  background: 'rgba(18, 10, 36, 0.7)',
                  border: '1px solid rgba(147,51,234,0.15)',
                  backdropFilter: 'blur(12px)',
                }}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <div
                  className="absolute top-0 left-0 right-0 h-[2px]"
                  style={{ background: 'linear-gradient(90deg, transparent, rgba(147,51,234,0.3), transparent)' }}
                />
                <h2
                  className="text-lg font-semibold text-[#e8dff5] mb-4"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  Quick Links
                </h2>
                <div className="space-y-2">
                  {[
                    { icon: Download, label: 'Download Agent', href: '/download', color: '#9333ea' },
                    { icon: BookOpen, label: 'How It Works', href: '/how-it-works', color: '#a855f7' },
                    { icon: MessageSquare, label: 'Send Feedback', href: '/feedback', color: '#00e676' },
                    { icon: BookOpen, label: 'Read Posts', href: '/posts', color: '#f59e0b' },
                  ].map((link) => (
                    <Link
                      key={link.label}
                      href={link.href}
                      className="flex items-center gap-3 p-3 rounded-lg transition-all duration-200 hover:bg-[rgba(147,51,234,0.05)] group"
                    >
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-all duration-200 group-hover:scale-105"
                        style={{ background: `${link.color}10`, border: `1px solid ${link.color}20` }}
                      >
                        <link.icon className="w-4 h-4" style={{ color: link.color }} />
                      </div>
                      <span className="text-sm text-[#c4b5d9] group-hover:text-[#e8dff5] transition-colors">
                        {link.label}
                      </span>
                      <ExternalLink className="w-3 h-3 text-[#6b5a80] ml-auto opacity-0 group-hover:opacity-100 transition-opacity" />
                    </Link>
                  ))}
                </div>
              </motion.div>

              {/* Founding Member Card */}
              <motion.div
                className="p-6 rounded-xl relative overflow-hidden"
                style={{
                  background: 'linear-gradient(135deg, rgba(245,158,11,0.05), rgba(18,10,36,0.7))',
                  border: '1px solid rgba(245,158,11,0.15)',
                  backdropFilter: 'blur(12px)',
                }}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.35 }}
              >
                <div
                  className="absolute top-0 left-0 right-0 h-[2px]"
                  style={{ background: 'linear-gradient(90deg, transparent, rgba(245,158,11,0.5), transparent)' }}
                />
                <div className="flex items-center gap-2 mb-3">
                  <Crown className="w-5 h-5 text-[#f59e0b]" />
                  <h3
                    className="text-base font-semibold text-[#f59e0b]"
                    style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                  >
                    Founding Member
                  </h3>
                </div>
                <p className="text-sm text-[#c4b5d9] leading-relaxed">
                  You&apos;re one of the first people using Correlic. When paid plans launch,
                  you&apos;ll get <span className="text-[#f59e0b] font-semibold">up to 90% off</span> — locked for life.
                </p>
                <p className="text-xs text-[#6b5a80] mt-3">
                  Thank you for believing in this early.
                </p>
              </motion.div>
            </div>
          </div>
        </div>
      </main>
      <Footer />

      {/* Toast notification */}
      {toast && (
        <motion.div
          className="fixed bottom-6 right-6 z-50 max-w-sm"
          initial={{ opacity: 0, y: 20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.95 }}
        >
          <div
            className="flex items-start gap-3 px-4 py-3 rounded-xl shadow-2xl backdrop-blur-md"
            style={{
              background: toast.type === 'success'
                ? 'rgba(0,230,118,0.08)'
                : 'rgba(255,59,92,0.08)',
              border: `1px solid ${toast.type === 'success'
                ? 'rgba(0,230,118,0.3)'
                : 'rgba(255,59,92,0.3)'}`,
              boxShadow: toast.type === 'success'
                ? '0 8px 32px rgba(0,230,118,0.15)'
                : '0 8px 32px rgba(255,59,92,0.15)',
            }}
          >
            <div
              className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
              style={{
                background: toast.type === 'success'
                  ? 'rgba(0,230,118,0.15)'
                  : 'rgba(255,59,92,0.15)',
              }}
            >
              {toast.type === 'success'
                ? <Check className="w-4 h-4 text-[#00e676]" />
                : <AlertTriangle className="w-4 h-4 text-[#ff3b5c]" />
              }
            </div>
            <div className="flex-1 min-w-0">
              <p className={`text-sm ${toast.type === 'success' ? 'text-[#c4b5d9]' : 'text-[#c4b5d9]'}`}>
                {toast.message}
              </p>
            </div>
            <button
              onClick={() => setToast(null)}
              className="text-[#6b5a80] hover:text-[#c4b5d9] transition-colors shrink-0 p-0.5"
            >
              <span className="text-xs">&times;</span>
            </button>
          </div>
        </motion.div>
      )}
    </>
  )
}

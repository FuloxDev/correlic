'use client'

import { useState, useEffect, useCallback } from 'react'
import * as Tabs from '@radix-ui/react-tabs'
import {
  Users, MessageSquare, Key, BarChart3, Search,
  Check, X, Trash2, UserPlus, ChevronLeft, ChevronRight,
  Star, Shield, Eye, EyeOff, ArrowRight, LogOut,
  FileText, Upload, Play, Clock, Globe, GlobeLock,
} from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

// ── Types ────────────────────────────────────────────────────────

interface User {
  id: string
  email: string
  name: string
  company: string | null
  useCase: string | null
  role: string
  status: string
  createdAt: string
}

interface Stats {
  users: { total: number; waitlist: number; active: number; suspended: number }
  keys: { total: number; active: number }
  feedback: { total: number; avgRating: number }
}

interface FeedbackEntry {
  id: string
  userId: string | null
  rating: number
  category: string
  subject: string
  message: string
  email: string | null
  createdAt: string
}

interface ApiKey {
  id: string
  userId: string
  userEmail: string
  keyPrefix: string
  name: string
  lastUsedAt: string | null
  revokedAt: string | null
  expiresAt: string | null
  createdAt: string
}

// ── Helpers ──────────────────────────────────────────────────────

const statusColors: Record<string, string> = {
  active: 'bg-[rgba(0,230,118,0.12)] text-[#00e676] border-[rgba(0,230,118,0.3)]',
  waitlist: 'bg-[rgba(240,200,0,0.12)] text-[#f0c800] border-[rgba(240,200,0,0.3)]',
  suspended: 'bg-[rgba(255,59,92,0.12)] text-[#ff3b5c] border-[rgba(255,59,92,0.3)]',
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`px-2 py-0.5 rounded-md text-xs font-medium border ${statusColors[status] || 'text-[#6b5a80]'}`}>
      {status}
    </span>
  )
}

function StatCard({ label, value, icon: Icon }: { label: string; value: string | number; icon: React.ElementType }) {
  return (
    <div className="glass-card p-5 space-y-2">
      <div className="flex items-center gap-2 text-[#6b5a80]">
        <Icon className="w-4 h-4" />
        <span className="text-xs font-medium uppercase tracking-wider">{label}</span>
      </div>
      <p className="text-2xl font-bold text-[#e8dff5]" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
        {value}
      </p>
    </div>
  )
}

function formatDate(d: string) {
  return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

// ── Admin Login ──────────────────────────────────────────────────

function AdminLogin({ onLogin }: { onLogin: (token: string) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const { data, error: err } = await api<{ accessToken: string; user: { role: string } }>('/auth/login', {
      method: 'POST',
      body: { email, password },
    })

    setLoading(false)

    if (err) {
      setError(err)
      return
    }

    if (!data?.accessToken) {
      setError('Login failed')
      return
    }

    // Verify admin role by trying to access admin stats
    const { status } = await api('/admin/stats', { token: data.accessToken })
    if (status === 403) {
      setError('Access denied — admin privileges required')
      return
    }
    if (status === 401) {
      setError('Authentication failed')
      return
    }

    onLogin(data.accessToken)
  }

  return (
    <div className="min-h-screen bg-[#0a0612] flex items-center justify-center px-4">
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse 60% 50% at 50% 40%, rgba(147,51,234,0.04) 0%, transparent 70%)',
        }}
      />
      <div className="w-full max-w-sm space-y-6 relative z-10">
        <div className="flex flex-col items-center gap-3 text-center">
          <div className="w-14 h-14 rounded-full bg-[rgba(147,51,234,0.08)] border border-[rgba(147,51,234,0.2)] flex items-center justify-center">
            <Shield className="w-7 h-7 text-[#9333ea]" />
          </div>
          <h1
            className="text-2xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Admin Access
          </h1>
          <p className="text-sm text-[#6b5a80]">Sign in with your admin credentials</p>
        </div>

        <form onSubmit={handleSubmit} className="glass-card p-7 space-y-5">
          {error && (
            <div className="px-4 py-2.5 rounded-xl bg-[rgba(255,59,92,0.08)] border border-[rgba(255,59,92,0.2)] text-sm text-[#ff3b5c]">
              {error}
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#c4b5d9]">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@correlic.com"
              className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] transition-all"
              style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#c4b5d9]">Password</label>
            <div className="relative">
              <input
                type={showPw ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 pr-10 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] transition-all"
                style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}
              />
              <button
                type="button"
                onClick={() => setShowPw(!showPw)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[#6b5a80] hover:text-[#c4b5d9] transition-colors"
              >
                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <Button type="submit" variant="primary" size="md" className="w-full" disabled={loading}>
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-[#0a0612] border-t-transparent rounded-full animate-spin" />
                Verifying…
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Sign In
                <ArrowRight className="w-3.5 h-3.5" />
              </span>
            )}
          </Button>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function AdminPage() {
  const [token, setToken] = useState<string | null>(null)
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(false)

  function handleLogin(accessToken: string) {
    setToken(accessToken)
    setLoading(true)
    api<Stats>('/admin/stats', { token: accessToken }).then(({ data }) => {
      setStats(data || null)
      setLoading(false)
    })
  }

  function handleLogout() {
    setToken(null)
    setStats(null)
  }

  if (!token) {
    return <AdminLogin onLogin={handleLogin} />
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0612] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-[#9333ea] border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-[#0a0612] py-8">
      <div className="max-w-6xl mx-auto px-4">
        <div className="flex items-center justify-between mb-6">
          <h1
            className="text-2xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Admin Dashboard
          </h1>
          <Button variant="ghost" size="sm" onClick={handleLogout}>
            <LogOut className="w-3.5 h-3.5" />
            Sign Out
          </Button>
        </div>

        <Tabs.Root defaultValue="dashboard">
          <Tabs.List className="flex gap-1 mb-6 border-b border-[rgba(147,51,234,0.08)] pb-px">
            {[
              { value: 'dashboard', label: 'Dashboard', icon: BarChart3 },
              { value: 'users', label: 'Users', icon: Users },
              { value: 'waitlist', label: 'Waitlist', icon: UserPlus },
              { value: 'posts', label: 'Posts', icon: FileText },
              { value: 'feedback', label: 'Feedback', icon: MessageSquare },
              { value: 'keys', label: 'API Keys', icon: Key },
            ].map((tab) => (
              <Tabs.Trigger
                key={tab.value}
                value={tab.value}
                className="flex items-center gap-1.5 px-4 py-2 text-sm text-[#6b5a80] hover:text-[#c4b5d9] data-[state=active]:text-[#9333ea] data-[state=active]:border-b-2 data-[state=active]:border-[#9333ea] transition-colors -mb-px cursor-pointer"
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </Tabs.Trigger>
            ))}
          </Tabs.List>

          <Tabs.Content value="dashboard">
            {stats && <DashboardTab stats={stats} />}
          </Tabs.Content>
          <Tabs.Content value="users">
            <UsersTab token={token} />
          </Tabs.Content>
          <Tabs.Content value="waitlist">
            <WaitlistTab token={token} />
          </Tabs.Content>
          <Tabs.Content value="posts">
            <PostsTab token={token} />
          </Tabs.Content>
          <Tabs.Content value="feedback">
            <FeedbackTab token={token} />
          </Tabs.Content>
          <Tabs.Content value="keys">
            <KeysTab token={token} />
          </Tabs.Content>
        </Tabs.Root>
      </div>
    </div>
  )
}

// ── Dashboard Tab ────────────────────────────────────────────────

function DashboardTab({ stats }: { stats: Stats }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard label="Total Users" value={stats.users.total} icon={Users} />
      <StatCard label="Waitlist" value={stats.users.waitlist} icon={UserPlus} />
      <StatCard label="Active" value={stats.users.active} icon={Check} />
      <StatCard label="Suspended" value={stats.users.suspended} icon={X} />
      <StatCard label="API Keys" value={stats.keys.active} icon={Key} />
      <StatCard label="Total Keys" value={stats.keys.total} icon={Key} />
      <StatCard label="Feedback" value={stats.feedback.total} icon={MessageSquare} />
      <StatCard label="Avg Rating" value={stats.feedback.avgRating || '—'} icon={Star} />
    </div>
  )
}

// ── Users Tab ────────────────────────────────────────────────────

function UsersTab({ token }: { token: string }) {
  const [users, setUsers] = useState<User[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<Partial<User>>({})

  const fetchUsers = useCallback(async () => {
    setLoading(true)
    const params = new URLSearchParams({ page: String(page), limit: '20' })
    if (search) params.set('search', search)
    if (statusFilter) params.set('status', statusFilter)

    const { data } = await api<{ users: User[]; total: number }>(`/admin/users?${params}`, { token })
    setUsers(data?.users || [])
    setTotal(data?.total || 0)
    setLoading(false)
  }, [page, search, statusFilter])

  useEffect(() => { fetchUsers() }, [fetchUsers])

  async function handleUpdate(id: string) {
    await api(`/admin/users/${id}`, { method: 'PATCH', body: editForm, token })
    setEditingId(null)
    setEditForm({})
    fetchUsers()
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this user? This cannot be undone.')) return
    await api(`/admin/users/${id}`, { method: 'DELETE', token })
    fetchUsers()
  }

  const totalPages = Math.ceil(total / 20)

  return (
    <div className="space-y-4">
      <div className="flex gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b5a80]" />
          <input
            placeholder="Search users..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl pl-9 pr-4 py-2 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)]"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1) }}
          className="bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2 text-sm text-[#e8dff5] focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="waitlist">Waitlist</option>
          <option value="suspended">Suspended</option>
        </select>
      </div>

      {loading ? (
        <div className="text-center py-8 text-[#6b5a80]">Loading...</div>
      ) : (
        <div className="space-y-2">
          {users.map((user) => (
            <div key={user.id} className="glass-card p-4">
              {editingId === user.id ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <input
                      defaultValue={user.name}
                      onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                      placeholder="Name"
                      className="bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-lg px-3 py-1.5 text-sm text-[#e8dff5]"
                    />
                    <input
                      defaultValue={user.email}
                      onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                      placeholder="Email"
                      className="bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-lg px-3 py-1.5 text-sm text-[#e8dff5]"
                    />
                    <select
                      defaultValue={user.status}
                      onChange={(e) => setEditForm({ ...editForm, status: e.target.value })}
                      className="bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-lg px-3 py-1.5 text-sm text-[#e8dff5]"
                    >
                      <option value="active">Active</option>
                      <option value="waitlist">Waitlist</option>
                      <option value="suspended">Suspended</option>
                    </select>
                    <select
                      defaultValue={user.role}
                      onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                      className="bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-lg px-3 py-1.5 text-sm text-[#e8dff5]"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div className="flex gap-2">
                    <Button variant="primary" size="sm" onClick={() => handleUpdate(user.id)}>Save</Button>
                    <Button variant="ghost" size="sm" onClick={() => { setEditingId(null); setEditForm({}) }}>Cancel</Button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[#e8dff5] font-medium">{user.name}</span>
                      <StatusBadge status={user.status} />
                      {user.role === 'admin' && (
                        <span className="px-2 py-0.5 rounded-md text-xs font-medium border bg-[rgba(147,51,234,0.12)] text-[#9333ea] border-[rgba(147,51,234,0.3)]">
                          admin
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-xs text-[#6b5a80]">
                      <span>{user.email}</span>
                      {user.company && <span>{user.company}</span>}
                      <span>{formatDate(user.createdAt)}</span>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <Button variant="ghost" size="sm" onClick={() => setEditingId(user.id)}>Edit</Button>
                    <Button variant="destructive" size="sm" onClick={() => handleDelete(user.id)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ))}

          {users.length === 0 && (
            <div className="text-center py-8 text-[#6b5a80]">No users found</div>
          )}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-4">
          <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="w-4 h-4" />
          </Button>
          <span className="text-sm text-[#6b5a80]">Page {page} of {totalPages}</span>
          <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      )}
    </div>
  )
}

// ── Waitlist Tab ─────────────────────────────────────────────────

function WaitlistTab({ token }: { token: string }) {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [approvedKey, setApprovedKey] = useState<{ email: string; key: string } | null>(null)

  const fetchWaitlist = useCallback(async () => {
    setLoading(true)
    const { data } = await api<{ users: User[] }>('/admin/waitlist', { token })
    setUsers(data?.users || [])
    setLoading(false)
  }, [])

  useEffect(() => { fetchWaitlist() }, [fetchWaitlist])

  async function handleApprove(id: string) {
    const { data } = await api<{ email: string; apiKey: string }>(`/admin/users/${id}/approve`, { method: 'PATCH', token })
    if (data?.apiKey) {
      setApprovedKey({ email: data.email, key: data.apiKey })
    }
    fetchWaitlist()
  }

  if (loading) return <div className="text-center py-8 text-[#6b5a80]">Loading...</div>

  return (
    <div className="space-y-2">
      {approvedKey && (
        <div className="glass-card p-4 space-y-2 border-[rgba(0,230,118,0.3)]" style={{ borderColor: 'rgba(0,230,118,0.3)' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Check className="w-4 h-4 text-[#00e676]" />
              <span className="text-sm text-[#00e676] font-medium">Approved: {approvedKey.email}</span>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setApprovedKey(null)}>
              <X className="w-3.5 h-3.5" />
            </Button>
          </div>
          <div className="flex items-center gap-2">
            <code className="text-xs text-[#e8dff5] font-mono bg-[#0a0612] px-3 py-1.5 rounded-lg flex-1 truncate">{approvedKey.key}</code>
          </div>
          <p className="text-xs text-[#6b5a80]">API key generated. The user can view it from their account page.</p>
        </div>
      )}

      {users.length === 0 ? (
        <div className="text-center py-12 text-[#6b5a80]">
          <UserPlus className="w-8 h-8 mx-auto mb-2 opacity-50" />
          No users in waitlist
        </div>
      ) : (
        users.map((user) => (
          <div key={user.id} className="glass-card p-4 flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-[#e8dff5] font-medium">{user.name}</span>
              <div className="flex items-center gap-3 text-xs text-[#6b5a80]">
                <span>{user.email}</span>
                {user.company && <span>{user.company}</span>}
                {user.useCase && <span>{user.useCase}</span>}
                <span>{formatDate(user.createdAt)}</span>
              </div>
            </div>
            <Button variant="primary" size="sm" onClick={() => handleApprove(user.id)}>
              <Check className="w-3.5 h-3.5" />
              Approve
            </Button>
          </div>
        ))
      )}
    </div>
  )
}

// ── Feedback Tab ─────────────────────────────────────────────────

function FeedbackTab({ token }: { token: string }) {
  const [entries, setEntries] = useState<FeedbackEntry[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)

  const fetchFeedback = useCallback(async () => {
    setLoading(true)
    const { data } = await api<{ feedback: FeedbackEntry[]; total: number }>(`/admin/feedback?page=${page}&limit=20`, { token })
    setEntries(data?.feedback || [])
    setTotal(data?.total || 0)
    setLoading(false)
  }, [page])

  useEffect(() => { fetchFeedback() }, [fetchFeedback])

  async function handleDelete(id: string) {
    if (!confirm('Delete this feedback?')) return
    await api(`/admin/feedback/${id}`, { method: 'DELETE', token })
    fetchFeedback()
  }

  const totalPages = Math.ceil(total / 20)

  if (loading) return <div className="text-center py-8 text-[#6b5a80]">Loading...</div>

  return (
    <div className="space-y-2">
      {entries.length === 0 ? (
        <div className="text-center py-12 text-[#6b5a80]">
          <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-50" />
          No feedback yet
        </div>
      ) : (
        entries.map((entry) => (
          <div key={entry.id} className="glass-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex gap-0.5">
                  {[1, 2, 3, 4, 5].map((s) => (
                    <Star key={s} className={`w-3.5 h-3.5 ${s <= entry.rating ? 'text-[#f0c800] fill-[#f0c800]' : 'text-[#6b5a80]'}`} />
                  ))}
                </div>
                <span className="px-2 py-0.5 rounded-md text-xs border border-[rgba(147,51,234,0.2)] text-[#c4b5d9]">
                  {entry.category}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-[#6b5a80]">{formatDate(entry.createdAt)}</span>
                <Button variant="destructive" size="sm" onClick={() => handleDelete(entry.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
            <p className="text-sm font-medium text-[#e8dff5]">{entry.subject}</p>
            <p className="text-sm text-[#c4b5d9]">{entry.message}</p>
            {entry.email && <p className="text-xs text-[#6b5a80]">From: {entry.email}</p>}
          </div>
        ))
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-4">
          <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="w-4 h-4" />
          </Button>
          <span className="text-sm text-[#6b5a80]">Page {page} of {totalPages}</span>
          <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      )}
    </div>
  )
}

// ── API Keys Tab ─────────────────────────────────────────────────

function KeysTab({ token }: { token: string }) {
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)

  const fetchKeys = useCallback(async () => {
    setLoading(true)
    const { data } = await api<{ keys: ApiKey[]; total: number }>(`/admin/keys?page=${page}&limit=20`, { token })
    setKeys(data?.keys || [])
    setTotal(data?.total || 0)
    setLoading(false)
  }, [page])

  useEffect(() => { fetchKeys() }, [fetchKeys])

  async function handleRevoke(id: string) {
    if (!confirm('Revoke this API key?')) return
    await api(`/admin/keys/${id}`, { method: 'DELETE', token })
    fetchKeys()
  }

  async function handleExtend(id: string) {
    const days = prompt('Extend by how many days?', '90')
    if (!days) return
    await api(`/admin/keys/${id}/extend`, { method: 'PATCH', body: { extendDays: parseInt(days) }, token })
    fetchKeys()
  }

  function expiryLabel(expiresAt: string | null): { text: string; color: string } {
    if (!expiresAt) return { text: 'No expiry', color: '#6b5a80' }
    const diff = new Date(expiresAt).getTime() - Date.now()
    const days = Math.ceil(diff / 86_400_000)
    if (days < 0) return { text: 'Expired', color: '#ff3b5c' }
    if (days <= 1) return { text: 'Expires today', color: '#ff3b5c' }
    if (days <= 7) return { text: `${days}d left`, color: '#ff7a2f' }
    if (days <= 14) return { text: `${days}d left`, color: '#f0c800' }
    return { text: `${days}d left`, color: '#00e676' }
  }

  const totalPages = Math.ceil(total / 20)

  if (loading) return <div className="text-center py-8 text-[#6b5a80]">Loading...</div>

  return (
    <div className="space-y-2">
      {keys.length === 0 ? (
        <div className="text-center py-12 text-[#6b5a80]">
          <Key className="w-8 h-8 mx-auto mb-2 opacity-50" />
          No API keys yet
        </div>
      ) : (
        keys.map((key) => (
          <div key={key.id} className="glass-card p-4 flex items-center justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <code className="text-sm text-[#9333ea] font-mono">{key.keyPrefix}...</code>
                <span className="text-sm text-[#e8dff5]">{key.name}</span>
                {key.revokedAt && (
                  <span className="px-2 py-0.5 rounded-md text-xs border border-[rgba(255,59,92,0.3)] text-[#ff3b5c]">
                    revoked
                  </span>
                )}
                {!key.revokedAt && (() => {
                  const exp = expiryLabel(key.expiresAt)
                  return (
                    <span className="px-2 py-0.5 rounded-md text-xs" style={{ color: exp.color, borderColor: exp.color + '40', borderWidth: 1 }}>
                      {exp.text}
                    </span>
                  )
                })()}
              </div>
              <div className="flex items-center gap-3 text-xs text-[#6b5a80]">
                <span>{key.userEmail}</span>
                <span>Created {formatDate(key.createdAt)}</span>
                {key.lastUsedAt && <span>Last used {formatDate(key.lastUsedAt)}</span>}
              </div>
            </div>
            {!key.revokedAt && (
              <div className="flex gap-1">
                <Button variant="outline" size="sm" onClick={() => handleExtend(key.id)}>
                  Extend
                </Button>
                <Button variant="destructive" size="sm" onClick={() => handleRevoke(key.id)}>
                  Revoke
                </Button>
              </div>
            )}
          </div>
        ))
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-4">
          <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="w-4 h-4" />
          </Button>
          <span className="text-sm text-[#6b5a80]">Page {page} of {totalPages}</span>
          <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      )}
    </div>
  )
}

// ── Posts Tab ────────────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001'

interface AdminPost {
  id: string
  title: string
  slug: string
  type: string
  externalUrl: string | null
  excerpt: string | null
  content: string | null
  thumbnailUrl: string | null
  mediaUrl: string | null
  mediaDuration: number | null
  authorName: string
  published: boolean
  publishedAt: string | null
  createdAt: string
  updatedAt: string
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

function PostsTab({ token }: { token: string }) {
  const [posts, setPosts] = useState<AdminPost[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)

  // Create form state
  const [createForm, setCreateForm] = useState({
    title: '',
    slug: '',
    type: 'video' as 'video' | 'article',
    externalUrl: '',
    excerpt: '',
    content: '',
    authorName: '',
    mediaDuration: '',
    published: false,
  })
  const [thumbnailFile, setThumbnailFile] = useState<File | null>(null)
  const [mediaFile, setMediaFile] = useState<File | null>(null)
  const [creating, setCreating] = useState(false)
  const [uploadProgress, setUploadProgress] = useState('')
  const [scraping, setScraping] = useState(false)
  const [ogThumbnail, setOgThumbnail] = useState<string | null>(null)

  const fetchPosts = useCallback(async () => {
    setLoading(true)
    const params = new URLSearchParams({ page: String(page), limit: '20' })
    if (search) params.set('search', search)
    const { data } = await api<{ posts: AdminPost[]; total: number }>(`/admin/posts?${params}`, { token })
    setPosts(data?.posts || [])
    setTotal(data?.total || 0)
    setLoading(false)
  }, [page, search, token])

  useEffect(() => { fetchPosts() }, [fetchPosts])

  async function uploadFile(file: File, folder: 'thumbnails' | 'media'): Promise<string | null> {
    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch(`${API_BASE}/admin/posts/upload?folder=${folder}`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.message || 'Upload failed')
      return data.url
    } catch (err) {
      alert(`Upload failed: ${(err as Error).message}`)
      return null
    }
  }

  async function handleScrapeUrl() {
    if (!createForm.externalUrl) return
    setScraping(true)
    const { data, error } = await api<{
      title: string | null
      description: string | null
      image: string | null
      siteName: string | null
      author: string | null
    }>('/admin/posts/scrape', { method: 'POST', body: { url: createForm.externalUrl }, token })
    setScraping(false)

    if (error || !data) {
      alert(error || 'Failed to fetch metadata')
      return
    }

    setCreateForm((prev) => ({
      ...prev,
      title: data.title || prev.title,
      slug: data.title ? slugify(data.title) : prev.slug,
      excerpt: data.description || prev.excerpt,
      authorName: data.author || data.siteName || prev.authorName,
    }))
    if (data.image) setOgThumbnail(data.image)
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setCreating(true)

    let thumbnailUrl: string | null = null
    let mediaUrl: string | null = null

    if (thumbnailFile) {
      setUploadProgress('Uploading thumbnail...')
      thumbnailUrl = await uploadFile(thumbnailFile, 'thumbnails')
      if (!thumbnailUrl) { setCreating(false); setUploadProgress(''); return }
    }

    if (mediaFile) {
      setUploadProgress('Uploading media file...')
      mediaUrl = await uploadFile(mediaFile, 'media')
      if (!mediaUrl) { setCreating(false); setUploadProgress(''); return }
    }

    setUploadProgress('Creating post...')

    const body: Record<string, unknown> = {
      title: createForm.title,
      slug: createForm.slug,
      type: createForm.type,
      authorName: createForm.authorName,
      published: createForm.published,
    }
    if (createForm.externalUrl) body.externalUrl = createForm.externalUrl
    if (createForm.excerpt) body.excerpt = createForm.excerpt
    if (createForm.content) body.content = createForm.content
    if (createForm.mediaDuration) body.mediaDuration = parseInt(createForm.mediaDuration, 10)
    if (thumbnailUrl) body.thumbnailUrl = thumbnailUrl
    else if (ogThumbnail) body.thumbnailUrl = ogThumbnail
    if (mediaUrl) body.mediaUrl = mediaUrl
    if (createForm.published) body.publishedAt = new Date().toISOString()

    const { error } = await api('/admin/posts', { method: 'POST', body, token })

    setCreating(false)
    setUploadProgress('')

    if (error) {
      alert(error)
      return
    }

    setCreateForm({ title: '', slug: '', type: 'video', externalUrl: '', excerpt: '', content: '', authorName: '', mediaDuration: '', published: false })
    setThumbnailFile(null)
    setMediaFile(null)
    setOgThumbnail(null)
    setShowCreate(false)
    fetchPosts()
  }

  async function handleTogglePublish(post: AdminPost) {
    const published = !post.published
    const body: Record<string, unknown> = { published }
    if (published && !post.publishedAt) body.publishedAt = new Date().toISOString()
    await api(`/admin/posts/${post.id}`, { method: 'PATCH', body, token })
    fetchPosts()
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this post? This will also remove uploaded files.')) return
    await api(`/admin/posts/${id}`, { method: 'DELETE', token })
    fetchPosts()
  }

  const totalPages = Math.ceil(total / 20)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b5a80]" />
          <input
            placeholder="Search posts..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl pl-9 pr-4 py-2 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)]"
          />
        </div>
        <Button variant="primary" size="sm" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? <X className="w-3.5 h-3.5" /> : <Upload className="w-3.5 h-3.5" />}
          {showCreate ? 'Cancel' : 'New Post'}
        </Button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={handleCreate} className="glass-card p-6 space-y-4" style={{ borderColor: 'rgba(147,51,234,0.25)' }}>
          <h3 className="text-sm font-semibold text-[#e8dff5] uppercase tracking-wider">Create New Post</h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">Title</label>
              <input
                required
                value={createForm.title}
                onChange={(e) => setCreateForm({ ...createForm, title: e.target.value, slug: slugify(e.target.value) })}
                placeholder="Post title"
                className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)]"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">Slug</label>
              <input
                required
                value={createForm.slug}
                onChange={(e) => setCreateForm({ ...createForm, slug: e.target.value })}
                placeholder="url-friendly-slug"
                className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] font-mono"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">Type</label>
              <select
                value={createForm.type}
                onChange={(e) => setCreateForm({ ...createForm, type: e.target.value as 'video' | 'article' })}
                className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] focus:outline-none focus:border-[rgba(147,51,234,0.4)]"
              >
                <option value="video">Video</option>
                <option value="article">Article</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">Author Name</label>
              <input
                required
                value={createForm.authorName}
                onChange={(e) => setCreateForm({ ...createForm, authorName: e.target.value })}
                placeholder="Author name"
                className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)]"
              />
            </div>
          </div>

          {createForm.type === 'video' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-[#c4b5d9]">Duration (seconds)</label>
                <input
                  type="number"
                  min="0"
                  value={createForm.mediaDuration}
                  onChange={(e) => setCreateForm({ ...createForm, mediaDuration: e.target.value })}
                  placeholder="e.g. 90 for 1:30"
                  className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] font-mono"
                />
              </div>
            </div>
          )}

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#c4b5d9]">Excerpt</label>
            <input
              value={createForm.excerpt}
              onChange={(e) => setCreateForm({ ...createForm, excerpt: e.target.value })}
              placeholder="Short summary for post cards"
              className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)]"
            />
          </div>

          {createForm.type === 'article' && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-[#c4b5d9]">Article URL (Hashnode, etc.)</label>
                <div className="flex gap-2">
                  <input
                    value={createForm.externalUrl}
                    onChange={(e) => setCreateForm({ ...createForm, externalUrl: e.target.value })}
                    placeholder="https://yourblog.hashnode.dev/your-article"
                    className="flex-1 bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)]"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="md"
                    disabled={!createForm.externalUrl || scraping}
                    onClick={handleScrapeUrl}
                  >
                    {scraping ? (
                      <span className="flex items-center gap-2">
                        <span className="w-3.5 h-3.5 border-2 border-[#9333ea] border-t-transparent rounded-full animate-spin" />
                        Fetching...
                      </span>
                    ) : (
                      'Fetch Metadata'
                    )}
                  </Button>
                </div>
              </div>
              {ogThumbnail && (
                <div className="flex items-center gap-3 p-3 rounded-xl bg-[rgba(0,230,118,0.06)] border border-[rgba(0,230,118,0.15)]">
                  <img src={ogThumbnail} alt="OG preview" className="w-24 h-14 rounded-lg object-cover shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs text-[#00e676] font-medium mb-0.5">Metadata fetched</p>
                    <p className="text-xs text-[#6b5a80] truncate">Thumbnail, title, and excerpt auto-filled from page</p>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">
                Thumbnail{createForm.type === 'video' ? ' (optional — video preview used if empty)' : ''}
              </label>
              <label className="flex items-center gap-3 w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm cursor-pointer hover:border-[rgba(147,51,234,0.3)] transition-colors">
                <Upload className="w-4 h-4 text-[#6b5a80] shrink-0" />
                <span className={`truncate ${thumbnailFile ? 'text-[#e8dff5]' : 'text-[#6b5a80]'}`}>
                  {thumbnailFile ? thumbnailFile.name : 'Choose image...'}
                </span>
                <input
                  type="file"
                  accept="image/jpeg,image/png,image/webp,image/gif"
                  className="hidden"
                  onChange={(e) => setThumbnailFile(e.target.files?.[0] || null)}
                />
              </label>
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-[#c4b5d9]">
                {createForm.type === 'video' ? 'Video File' : 'Media File (optional)'}
              </label>
              <label className="flex items-center gap-3 w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm cursor-pointer hover:border-[rgba(147,51,234,0.3)] transition-colors">
                {createForm.type === 'video' ? (
                  <Play className="w-4 h-4 text-[#6b5a80] shrink-0" />
                ) : (
                  <Upload className="w-4 h-4 text-[#6b5a80] shrink-0" />
                )}
                <span className={`truncate ${mediaFile ? 'text-[#e8dff5]' : 'text-[#6b5a80]'}`}>
                  {mediaFile ? mediaFile.name : createForm.type === 'video' ? 'Choose video...' : 'Choose file...'}
                </span>
                <input
                  type="file"
                  accept={createForm.type === 'video' ? 'video/mp4,video/webm,video/quicktime' : 'image/jpeg,image/png,image/webp,video/mp4'}
                  className="hidden"
                  onChange={(e) => setMediaFile(e.target.files?.[0] || null)}
                />
              </label>
            </div>
          </div>

          <div className="flex items-center gap-6 pt-2">
            <label className="flex items-center gap-2 text-sm text-[#c4b5d9] cursor-pointer">
              <input
                type="checkbox"
                checked={createForm.published}
                onChange={(e) => setCreateForm({ ...createForm, published: e.target.checked })}
                className="w-4 h-4 rounded border-[rgba(147,51,234,0.3)] bg-[#0a0612] text-[#9333ea] focus:ring-[#9333ea] focus:ring-offset-0"
              />
              Publish immediately
            </label>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <Button type="submit" variant="primary" size="md" disabled={creating}>
              {creating ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-[#0a0612] border-t-transparent rounded-full animate-spin" />
                  {uploadProgress || 'Creating...'}
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Upload className="w-4 h-4" />
                  Create Post
                </span>
              )}
            </Button>
            <Button type="button" variant="ghost" size="md" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      {/* Posts List */}
      {loading ? (
        <div className="text-center py-8 text-[#6b5a80]">Loading...</div>
      ) : posts.length === 0 ? (
        <div className="text-center py-12 text-[#6b5a80]">
          <FileText className="w-8 h-8 mx-auto mb-2 opacity-50" />
          No posts yet
        </div>
      ) : (
        <div className="space-y-2">
          {posts.map((post) => (
            <div key={post.id} className="glass-card p-4 flex items-center justify-between">
              <div className="flex items-center gap-4 flex-1 min-w-0">
                {/* Thumbnail preview */}
                {post.thumbnailUrl ? (
                  <div className="w-16 h-10 rounded-lg overflow-hidden bg-[#120a24] shrink-0">
                    <img
                      src={post.thumbnailUrl.startsWith('http') ? post.thumbnailUrl : `${API_BASE}${post.thumbnailUrl}`}
                      alt=""
                      className="w-full h-full object-cover"
                    />
                  </div>
                ) : (
                  <div className="w-16 h-10 rounded-lg bg-[#120a24] shrink-0 flex items-center justify-center">
                    {post.type === 'video' ? (
                      <Play className="w-4 h-4 text-[#6b5a80]" />
                    ) : (
                      <FileText className="w-4 h-4 text-[#6b5a80]" />
                    )}
                  </div>
                )}

                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[#e8dff5] font-medium truncate">{post.title}</span>
                    <span className={`px-2 py-0.5 rounded-md text-xs font-medium border ${
                      post.type === 'video'
                        ? 'bg-[rgba(255,122,47,0.12)] text-[#ff7a2f] border-[rgba(255,122,47,0.3)]'
                        : 'bg-[rgba(240,200,0,0.12)] text-[#f0c800] border-[rgba(240,200,0,0.3)]'
                    }`}>
                      {post.type}
                    </span>
                    {post.published ? (
                      <span className="px-2 py-0.5 rounded-md text-xs font-medium border bg-[rgba(0,230,118,0.12)] text-[#00e676] border-[rgba(0,230,118,0.3)]">
                        published
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-md text-xs font-medium border bg-[rgba(107,90,128,0.12)] text-[#6b5a80] border-[rgba(107,90,128,0.3)]">
                        draft
                      </span>
                    )}
                    {post.type === 'video' && post.mediaDuration && (
                      <span className="flex items-center gap-1 text-xs text-[#6b5a80]">
                        <Clock className="w-3 h-3" />
                        {formatDuration(post.mediaDuration)}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-[#6b5a80]">
                    <span>{post.authorName}</span>
                    <span className="font-mono">{post.slug}</span>
                    <span>{formatDate(post.createdAt)}</span>
                  </div>
                </div>
              </div>

              <div className="flex gap-1 shrink-0 ml-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleTogglePublish(post)}
                  title={post.published ? 'Unpublish' : 'Publish'}
                >
                  {post.published ? <GlobeLock className="w-3.5 h-3.5" /> : <Globe className="w-3.5 h-3.5" />}
                  {post.published ? 'Unpublish' : 'Publish'}
                </Button>
                <Button variant="destructive" size="sm" onClick={() => handleDelete(post.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 pt-4">
          <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="w-4 h-4" />
          </Button>
          <span className="text-sm text-[#6b5a80]">Page {page} of {totalPages}</span>
          <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      )}
    </div>
  )
}

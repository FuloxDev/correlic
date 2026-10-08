'use client'

import { useCallback, useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { getAgents } from '@/lib/api-client'
import { usePolling } from '@/lib/use-polling'

/** An agent counts as online when it checked in within this window. */
const ONLINE_WINDOW_MS = 2 * 60 * 1000
const POLL_MS = 60 * 1000
const INSTALL_DOCS_URL = 'https://github.com/FuloxDev/correlic#quick-start'

type AgentsState = { kind: 'checking' } | { kind: 'online'; count: number } | { kind: 'offline' }

export default function AgentsIndicator() {
  const [state, setState] = useState<AgentsState>({ kind: 'checking' })

  const refresh = useCallback(async () => {
    try {
      const agents = (await getAgents()) ?? []
      const now = Date.now()
      const online = agents.filter(a => {
        if (!a.last_seen_at) return false
        const seen = new Date(a.last_seen_at).getTime()
        return Number.isFinite(seen) && now - seen <= ONLINE_WINDOW_MS
      })
      setState(online.length > 0 ? { kind: 'online', count: online.length } : { kind: 'offline' })
    } catch {
      // Keep whatever we knew; the backend banner reports outages.
      setState(prev => (prev.kind === 'checking' ? { kind: 'offline' } : prev))
    }
  }, [])

  usePolling(refresh, POLL_MS)

  const pill = 'flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap'
  const pillStyle = { backgroundColor: 'var(--theme-card)', border: '1px solid var(--theme-card-border)' }

  if (state.kind === 'online') {
    return (
      <div className={pill} style={pillStyle} role="status" aria-live="polite">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--low)', boxShadow: '0 0 6px var(--low)' }} aria-hidden="true" />
        <span style={{ color: 'var(--theme-text-secondary)' }}>
          {state.count} agent{state.count === 1 ? '' : 's'} online
        </span>
      </div>
    )
  }

  if (state.kind === 'offline') {
    return (
      <a
        href={INSTALL_DOCS_URL}
        target="_blank"
        rel="noreferrer"
        className={`${pill} hover:underline`}
        style={pillStyle}
        role="status"
        aria-live="polite"
        title="No agent has reported in the last 2 minutes. Open the install guide."
      >
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--critical)', boxShadow: '0 0 6px var(--critical)' }} aria-hidden="true" />
        <span style={{ color: 'var(--critical)' }}>No agent connected</span>
        <span className="hidden sm:inline" style={{ color: 'var(--theme-text-muted)' }}>· Install guide</span>
        <ExternalLink className="w-3 h-3" style={{ color: 'var(--theme-text-muted)' }} aria-hidden="true" />
      </a>
    )
  }

  return (
    <div className={pill} style={pillStyle} role="status" aria-live="polite">
      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: 'var(--theme-text-muted)' }} aria-hidden="true" />
      <span style={{ color: 'var(--theme-text-muted)' }}>Checking agents…</span>
    </div>
  )
}

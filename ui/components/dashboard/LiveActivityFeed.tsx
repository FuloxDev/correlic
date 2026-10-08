'use client'

import { useMemo, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileText, Globe, Terminal, Wifi, Clock, ArrowRight, Radio } from 'lucide-react'
import Link from 'next/link'
import { getAgentActivity, getEvents, type AgentActivityResponse, type AgentAction, type TelemetryEvent } from '@/lib/api-client'

const categoryIcons: Record<string, React.ReactNode> = {
    file: <FileText className="w-3.5 h-3.5" />,
    network: <Globe className="w-3.5 h-3.5" />,
    command: <Terminal className="w-3.5 h-3.5" />,
    dns: <Wifi className="w-3.5 h-3.5" />,
}

const significanceColors: Record<number, string> = {
    1: 'bg-white/20',
    2: 'bg-blue-400',
    3: 'bg-amber-400',
    4: 'bg-orange-500',
    5: 'bg-red-500',
}

const MAX_ITEMS = 50
const FETCH_WINDOW_MINUTES = 30

function formatTimeAgo(ts: string): string {
    const diff = Date.now() - new Date(ts).getTime()
    const secs = Math.floor(diff / 1000)
    if (secs < 60) return `${secs}s`
    const mins = Math.floor(secs / 60)
    if (mins < 60) return `${mins}m`
    const hrs = Math.floor(mins / 60)
    return `${hrs}h`
}

function eventToAction(evt: TelemetryEvent): AgentAction & { agentName: string } {
    const p = evt.payload || {}
    const category = mapEventCategory(evt.event_type, p)
    const action = buildEventLabel(evt.event_type, p)
    const detail = buildEventDetail(evt.event_type, p)
    const significance = mapEventSignificance(evt.event_type, p)

    return {
        timestamp: evt.timestamp || evt.created_at,
        category,
        action,
        detail,
        significance,
        event_id: evt.id,
        event_type: evt.event_type,
        process_pid: (p.pid as number) || undefined,
        process_comm: (p.comm as string) || undefined,
        agentName: (p.ai_type as string) || evt.agent_id?.slice(0, 8) || 'agent',
    }
}

/** ai_tool_call events (correlic-hook) carry their fields under context. */
function hookContext(p: Record<string, unknown>): Record<string, unknown> {
    const ctx = p.context
    return ctx && typeof ctx === 'object' ? (ctx as Record<string, unknown>) : p
}

function mapEventCategory(eventType: string, p?: Record<string, unknown>): string {
    if (eventType === 'ai_tool_call') {
        const c = hookContext(p || {})
        if (c.command) return 'command'
        if (c.url) return 'network'
        return 'file'
    }
    if (eventType.startsWith('file_')) return 'file'
    if (eventType.startsWith('net_connect') || eventType === 'net_bind' || eventType === 'net_accept' || eventType === 'net_listen') return 'network'
    if (eventType === 'net_dns') return 'dns'
    if (eventType.startsWith('process_')) return 'command'
    return 'file'
}

function buildEventLabel(eventType: string, p: Record<string, unknown>): string {
    const path = p.file_path as string || p.target_path as string || ''
    const comm = p.comm as string || ''
    const fname = path ? path.split('/').pop() || path : ''

    switch (eventType) {
        case 'file_open':
            return `Opened ${fname}`
        case 'file_write':
            return `Wrote ${fname}`
        case 'net_connect': {
            const ip = p.dst_ip as string || p.target_ip as string || '?'
            const port = p.dst_port || p.target_port || '?'
            return `Connected to ${ip}:${port}`
        }
        case 'net_dns':
            return `DNS lookup ${p.domain as string || p.target_domain as string || '?'}`
        case 'process_exec':
            return `Ran: ${p.cmdline as string || comm || fname}`
        case 'process_exit':
            return `Process exited ${comm}`
        case 'ai_tool_call': {
            const c = hookContext(p)
            const what = (c.command as string) || (c.file_path as string) || (c.url as string) || (c.tool_name as string) || ''
            const prefix = c.decision === 'blocked' ? 'Blocked AI tool call' : 'AI tool call'
            return what ? `${prefix}: ${what}` : prefix
        }
        default:
            return `${eventType} ${fname || comm}`
    }
}

function buildEventDetail(eventType: string, p: Record<string, unknown>): string {
    if (eventType === 'ai_tool_call') {
        const c = hookContext(p)
        return (c.command as string) || (c.file_path as string) || (c.url as string) || ''
    }
    const path = p.file_path as string || p.target_path as string || ''
    const cmdline = p.cmdline as string || ''
    if (cmdline) return cmdline
    if (path) return path
    if (eventType === 'net_connect') return `${p.dst_ip || p.target_ip || ''}:${p.dst_port || p.target_port || ''}`
    return ''
}

function mapEventSignificance(eventType: string, p: Record<string, unknown>): number {
    if (eventType === 'ai_tool_call' && hookContext(p).decision === 'blocked') return 5
    const path = (p.file_path as string || p.target_path as string || '').toLowerCase()
    if (path.includes('/.ssh/') || path.includes('/etc/shadow') || path.includes('/etc/passwd')) return 5
    if (path.includes('.env') || path.includes('credentials') || path.includes('.pem')) return 4
    if (eventType === 'process_exec' || eventType === 'ai_tool_call') return 3
    if (eventType === 'net_connect' || eventType === 'net_dns') return 2
    return 1
}

interface LiveActivityFeedProps {
    /** Incremented by parent to trigger a refresh, syncing with parent's polling cycle */
    refreshTrigger?: number
}

export default function LiveActivityFeed({ refreshTrigger }: LiveActivityFeedProps) {
    const [loading, setLoading] = useState(true)
    const [activityData, setActivityData] = useState<AgentActivityResponse | null>(null)
    const [rawEvents, setRawEvents] = useState<TelemetryEvent[]>([])
    const [useRawFallback, setUseRawFallback] = useState(false)

    // Fetch on mount and whenever the parent triggers a refresh. Falls back to
    // raw telemetry when the activity endpoint has nothing to show.
    useEffect(() => {
        let cancelled = false
        const since = () => new Date(Date.now() - FETCH_WINDOW_MINUTES * 60000).toISOString()
        const loadRaw = () => getEvents({ since: since(), limit: MAX_ITEMS }).then(events => {
            if (cancelled) return
            setActivityData(null)
            setUseRawFallback(true)
            setRawEvents(events || [])
        })

        getAgentActivity(FETCH_WINDOW_MINUTES, 1)
            .then(activity => {
                if (cancelled) return
                const hasActions = activity?.agents?.some(a => a.actions?.length > 0)
                if (hasActions) {
                    setActivityData(activity)
                    setUseRawFallback(false)
                    return
                }
                return loadRaw()
            })
            .catch(() => loadRaw().catch(() => { /* keep previous data */ }))
            .finally(() => { if (!cancelled) setLoading(false) })

        return () => { cancelled = true }
    }, [refreshTrigger])

    const agentActions = useMemo(() => {
        if (!activityData?.agents) return []
        const actions: (AgentAction & { agentName: string })[] = []
        for (const agent of activityData.agents) {
            for (const action of agent.actions || []) {
                actions.push({ ...action, agentName: agent.agent_name || agent.ai_type })
            }
        }
        return actions
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .slice(0, MAX_ITEMS)
    }, [activityData])

    const rawActions = useMemo(() => {
        return rawEvents
            .map(eventToAction)
            .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
            .slice(0, MAX_ITEMS)
    }, [rawEvents])

    const allActions = useRawFallback ? rawActions : agentActions

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 flex flex-col h-[400px] overflow-hidden"
            style={{ borderColor: '#22c55e20' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #22c55e0c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #22c55e30, transparent 90%)' }} />

            {/* Header */}
            <div className="relative px-5 pt-5 pb-3">
                <div className="flex items-center gap-2">
                    <h3 className="text-sm font-semibold text-white/90">Live Activity</h3>
                    {!loading && allActions.length > 0 && (
                        <span className="flex items-center gap-1 text-[10px] text-emerald-400/70">
                            <Radio className="w-2.5 h-2.5 animate-pulse" />
                            live
                        </span>
                    )}
                    {allActions.length > 0 && (
                        <span className="text-[11px] text-white/20 tabular-nums ml-auto">
                            {allActions.length} events
                        </span>
                    )}
                </div>
            </div>

            {/* Event list */}
            <div className="flex-1 overflow-y-auto px-2 scrollbar-thin">
                <AnimatePresence initial={false}>
                    {loading && allActions.length === 0 && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="flex items-center justify-center h-full text-sm text-white/30"
                        >
                            Loading...
                        </motion.div>
                    )}
                    {!loading && allActions.length === 0 && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="flex flex-col items-center justify-center h-full gap-2"
                        >
                            <span className="text-sm text-white/30">No activity in this window</span>
                        </motion.div>
                    )}
                    {allActions.map((action, i) => (
                        <motion.div
                            key={action.event_id || `${action.timestamp}-${i}`}
                            layout
                            initial={{ opacity: 0, y: -8 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0, height: 0 }}
                            transition={{ duration: 0.2, delay: i < 10 ? i * 0.02 : 0 }}
                            className="flex items-start gap-2.5 px-3 py-2 mx-1 rounded-lg hover:bg-white/[0.04] transition-colors group cursor-default"
                        >
                            <div className="mt-0.5 text-white/25 group-hover:text-white/40 transition-colors">
                                {categoryIcons[action.category] || <ActivityIcon className="w-3.5 h-3.5" />}
                            </div>

                            <div className="flex-1 min-w-0">
                                <div className="text-[13px] text-white/75 truncate group-hover:text-white/90 transition-colors">
                                    {action.action}
                                </div>
                                <div className="text-[11px] text-white/20 truncate mt-0.5 max-h-0 group-hover:max-h-5 overflow-hidden transition-all duration-200">
                                    {action.detail}
                                </div>
                            </div>

                            <div className="flex items-center gap-2 shrink-0 mt-0.5">
                                <span className={`w-1.5 h-1.5 rounded-full ${significanceColors[action.significance] || significanceColors[1]}`} />
                                <span className="text-[11px] text-white/20 tabular-nums flex items-center gap-1">
                                    <Clock className="w-2.5 h-2.5" />
                                    {formatTimeAgo(action.timestamp)}
                                </span>
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>
            </div>

            {/* Footer */}
            <div className="px-5 py-3 border-t border-white/[0.06]">
                <Link
                    href="/timeline"
                    className="flex items-center justify-center gap-2 w-full py-2 text-[12px] font-medium text-white/40 hover:text-white/70 rounded-lg hover:bg-white/[0.04] transition-all duration-200 group"
                >
                    View full timeline
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                </Link>
            </div>
        </motion.div>
    )
}

function ActivityIcon({ className }: { className?: string }) {
    return (
        <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
        </svg>
    )
}

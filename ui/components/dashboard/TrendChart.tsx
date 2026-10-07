'use client'

import { useMemo, useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { getDashboardTrends, type TrendPoint } from '@/lib/api-client'

// Distinct colors for AI agent types — high contrast on dark backgrounds
const AGENT_COLORS: Record<string, string> = {
    claude:  '#f59e0b', // warm amber/gold
    cursor:  '#3b82f6', // bright blue
    copilot: '#10b981', // emerald green
    aider:   '#ec4899', // pink
    codeium: '#8b5cf6', // purple
    continue:'#ef4444', // red
    unknown: '#64748b', // slate
}

const FALLBACK_COLORS = ['#06b6d4', '#f97316', '#84cc16', '#e879f9', '#14b8a6', '#fb7185']

function getAgentColor(agent: string, idx: number): string {
    const key = agent.toLowerCase()
    if (AGENT_COLORS[key]) return AGENT_COLORS[key]
    return FALLBACK_COLORS[idx % FALLBACK_COLORS.length]
}

function formatTime(ts: string): string {
    const d = new Date(ts)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function capitalize(s: string): string {
    return s.charAt(0).toUpperCase() + s.slice(1)
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#64748b',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function formatRuleName(id: string): string {
    const name = id.replace(/^ai\./, '').replace(/_/g, ' ')
    return name.replace(/\b\w/g, c => c.toUpperCase())
}

interface FindingsTooltipContentProps {
    label: string
    payload: Array<{ name: string; value: number; color: string }>
    trends: TrendPoint[]
    pinned?: boolean
    onClose?: () => void
}

function FindingsTooltipContent({ label, payload, trends, pinned, onClose }: FindingsTooltipContentProps) {
    const total = payload.reduce((sum, e) => sum + (e.value || 0), 0)
    if (total === 0) return null

    const point = trends.find(p => p.timestamp === label)
    const severities = point?.finding_severities
    const rules = point?.finding_rules

    return (
        <div
            className="chart-tooltip-scroll backdrop-blur-xl bg-[#0f1729]/95 rounded-xl border border-white/10 shadow-2xl shadow-black/40 text-xs min-w-[180px] max-w-[260px] max-h-[280px]"
            onClick={(e) => e.stopPropagation()}
        >
            <div className="px-4 py-3">
                <div className="flex items-center justify-between mb-2">
                    <div className="text-[10px] uppercase tracking-wider text-white/40">{formatTime(label)}</div>
                    {pinned && (
                        <button onClick={onClose} className="text-white/30 hover:text-white/60 text-[10px] ml-2">
                            ESC
                        </button>
                    )}
                </div>

                {/* Agent breakdown */}
                {payload.filter(e => e.value > 0).map((entry) => (
                    <div key={entry.name} className="flex items-center justify-between gap-4 py-0.5">
                        <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full ring-2 ring-white/10" style={{ background: entry.color }} />
                            <span className="text-white/70">{entry.name}</span>
                        </div>
                        <span className="text-white font-medium tabular-nums">{entry.value.toLocaleString()}</span>
                    </div>
                ))}

                {payload.filter(e => e.value > 0).length > 1 && (
                    <div className="flex items-center justify-between gap-4 pt-1.5 mt-1.5 border-t border-white/10">
                        <span className="text-white/40">Total</span>
                        <span className="text-white font-semibold tabular-nums">{total.toLocaleString()}</span>
                    </div>
                )}

                {/* Severity breakdown */}
                {severities && Object.keys(severities).length > 0 && (
                    <div className="pt-1.5 mt-1.5 border-t border-white/10">
                        <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">By Severity</div>
                        {SEVERITY_ORDER.filter(s => severities[s] > 0).map(sev => (
                            <div key={sev} className="flex items-center justify-between gap-3 py-0.5">
                                <div className="flex items-center gap-1.5">
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEVERITY_COLORS[sev] || '#64748b' }} />
                                    <span className="text-white/50 capitalize">{sev}</span>
                                </div>
                                <span className="text-white/70 tabular-nums">{severities[sev]}</span>
                            </div>
                        ))}
                    </div>
                )}

                {/* Detection rules breakdown */}
                {rules && Object.keys(rules).length > 0 && (
                    <div className="pt-1.5 mt-1.5 border-t border-white/10">
                        <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Detection Rules</div>
                        {Object.entries(rules)
                            .sort(([, a], [, b]) => b - a)
                            .slice(0, 5)
                            .map(([rule, cnt]) => (
                                <div key={rule} className="flex items-center justify-between gap-3 py-0.5">
                                    <span className="text-white/50 truncate">{formatRuleName(rule)}</span>
                                    <span className="text-white/70 tabular-nums flex-shrink-0">{cnt}</span>
                                </div>
                            ))}
                        {Object.keys(rules).length > 5 && (
                            <div className="text-white/30 text-[10px] mt-0.5">+{Object.keys(rules).length - 5} more</div>
                        )}
                    </div>
                )}
            </div>
        </div>
    )
}

interface FindingsTooltipProps {
    active?: boolean
    payload?: Array<{ name: string; value: number; color: string }>
    label?: string
    trends: TrendPoint[]
}

function FindingsTooltip({ active, payload, label, trends }: FindingsTooltipProps) {
    if (!active || !payload || !label) return null
    const total = payload.reduce((sum, e) => sum + (e.value || 0), 0)
    if (total === 0) return null
    return <FindingsTooltipContent label={label} payload={payload} trends={trends} />
}

const timeRanges = [
    { label: '30m',  points: 12, interval: 3 },
    { label: '1h',   points: 12, interval: 5 },
    { label: '2h',   points: 24, interval: 5 },
    { label: '6h',   points: 24, interval: 15 },
    { label: '24h',  points: 24, interval: 60 },
]

// Default range index 2 = "2h" (points=24, interval=5) matches the parent page's fetch
const DEFAULT_RANGE_IDX = 2

interface TrendChartProps {
    /** Trends data from parent — avoids duplicate API call on initial load */
    initialTrends?: TrendPoint[]
}

export default function TrendChart({ initialTrends }: TrendChartProps) {
    const [rangeIdx, setRangeIdx] = useState(DEFAULT_RANGE_IDX)
    const [trends, setTrends] = useState<TrendPoint[]>(initialTrends || [])
    const [loading, setLoading] = useState(false)
    const [hiddenAgents, setHiddenAgents] = useState<Set<string>>(new Set())
    const [pinnedIndex, setPinnedIndex] = useState<number | null>(null)
    const [pinnedPos, setPinnedPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 })
    const chartContainerRef = useRef<HTMLDivElement>(null)

    const range = timeRanges[rangeIdx]

    // Update from parent when initial data changes (e.g. parent refresh)
    useEffect(() => {
        if (initialTrends && rangeIdx === DEFAULT_RANGE_IDX) {
            setTrends(initialTrends)
        }
    }, [initialTrends, rangeIdx])

    // Only fetch independently when user selects a different time range
    const fetchTrends = useCallback(async () => {
        if (rangeIdx === DEFAULT_RANGE_IDX && initialTrends) return
        try {
            setLoading(true)
            const res = await getDashboardTrends(range.points, range.interval)
            setTrends(res.points || [])
        } catch {
            // keep previous data on error
        } finally {
            setLoading(false)
        }
    }, [range.points, range.interval, rangeIdx, initialTrends])

    useEffect(() => {
        fetchTrends()
    }, [fetchTrends])

    // Clear pin on range change
    useEffect(() => { setPinnedIndex(null) }, [rangeIdx])

    // Close pinned tooltip on Escape or click outside
    useEffect(() => {
        if (pinnedIndex === null) return
        const handleKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') setPinnedIndex(null)
        }
        const handleClick = (e: MouseEvent) => {
            if (chartContainerRef.current && !chartContainerRef.current.contains(e.target as Node)) {
                setPinnedIndex(null)
            }
        }
        window.addEventListener('keydown', handleKey)
        window.addEventListener('click', handleClick)
        return () => {
            window.removeEventListener('keydown', handleKey)
            window.removeEventListener('click', handleClick)
        }
    }, [pinnedIndex])

    const toggleAgent = (agent: string) => {
        setHiddenAgents(prev => {
            const next = new Set(prev)
            if (next.has(agent)) next.delete(agent)
            else next.add(agent)
            return next
        })
    }

    // Collect all unique agent types across all points
    const agentTypes = useMemo(() => {
        const agents = new Set<string>()
        for (const p of trends) {
            if (p.agent_findings) {
                for (const agent of Object.keys(p.agent_findings)) {
                    agents.add(agent)
                }
            }
        }
        const known = ['claude', 'cursor', 'copilot', 'aider', 'codeium', 'continue']
        return [...agents].sort((a, b) => {
            const ai = known.indexOf(a.toLowerCase())
            const bi = known.indexOf(b.toLowerCase())
            if (ai !== -1 && bi !== -1) return ai - bi
            if (ai !== -1) return -1
            if (bi !== -1) return 1
            return a.localeCompare(b)
        })
    }, [trends])

    const hasAgentData = agentTypes.length > 0
    const visibleAgents = agentTypes.filter(a => !hiddenAgents.has(a))

    // Compute per-agent totals for legend badges
    const agentTotals = useMemo(() => {
        const totals: Record<string, number> = {}
        for (const p of trends) {
            if (p.agent_findings) {
                for (const [agent, count] of Object.entries(p.agent_findings)) {
                    totals[agent] = (totals[agent] || 0) + count
                }
            }
        }
        return totals
    }, [trends])

    // Build chart data with per-agent keys
    const data = useMemo(() =>
        trends.map((p) => {
            const point: Record<string, string | number> = {
                time: p.timestamp,
            }
            if (hasAgentData) {
                for (const agent of visibleAgents) {
                    point[capitalize(agent)] = p.agent_findings?.[agent] ?? 0
                }
            } else {
                point['Events'] = p.events
                point['Findings'] = p.findings
            }
            return point
        }),
    [trends, visibleAgents, hasAgentData])

    const hasData = data.length > 0 && data.some((d) => Object.values(d).some(v => typeof v === 'number' && v > 0))

    // Build payload for pinned tooltip
    const pinnedPayload = useMemo(() => {
        if (pinnedIndex === null || pinnedIndex >= trends.length) return null
        const p = trends[pinnedIndex]
        if (hasAgentData) {
            return visibleAgents.map((agent, i) => ({
                name: capitalize(agent),
                value: p.agent_findings?.[agent] ?? 0,
                color: getAgentColor(agent, i),
            }))
        }
        return [
            { name: 'Events', value: p.events, color: '#64748b' },
            { name: 'Findings', value: p.findings, color: '#f97316' },
        ]
    }, [pinnedIndex, trends, hasAgentData, visibleAgents])

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handleChartClick = (state: any, event: any) => {
        if (state && state.activeTooltipIndex !== undefined) {
            const idx = state.activeTooltipIndex as number
            if (pinnedIndex === idx) {
                setPinnedIndex(null)
            } else {
                // Position relative to chart container
                const rect = chartContainerRef.current?.getBoundingClientRect()
                const nativeEvent = event?.nativeEvent || event
                if (rect && nativeEvent) {
                    setPinnedPos({
                        x: nativeEvent.clientX - rect.left,
                        y: nativeEvent.clientY - rect.top,
                    })
                }
                setPinnedIndex(idx)
            }
        }
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 overflow-hidden"
            style={{ borderColor: '#3b82f620' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #3b82f60c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px z-10" style={{ background: 'linear-gradient(90deg, transparent 10%, #3b82f630, transparent 90%)' }} />
            {/* Header */}
            <div className="flex items-center justify-between px-5 pt-5 pb-3">
                <div>
                    <h3 className="text-sm font-semibold text-white/90">
                        {hasAgentData ? 'Findings by AI Agent' : 'Event & Finding Trends'}
                    </h3>
                    {hasAgentData && (
                        <p className="text-[11px] text-white/30 mt-0.5">Click agents to show/hide &middot; Click chart to pin tooltip</p>
                    )}
                </div>
                <div className="flex items-center gap-0.5 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                    {timeRanges.map((r, i) => (
                        <button
                            key={r.label}
                            onClick={() => setRangeIdx(i)}
                            className={`px-2.5 py-1 text-[11px] font-medium rounded-xl transition-all duration-200 ${
                                rangeIdx === i
                                    ? 'bg-white/10 text-white shadow-sm'
                                    : 'text-white/30 hover:text-white/60 hover:bg-white/[0.03]'
                            }`}
                        >
                            {r.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* Agent legend pills */}
            {hasAgentData && (
                <div className="flex items-center gap-2 px-5 pb-3 flex-wrap">
                    {agentTypes.map((agent, i) => {
                        const color = getAgentColor(agent, i)
                        const active = !hiddenAgents.has(agent)
                        const total = agentTotals[agent] || 0
                        return (
                            <button
                                key={agent}
                                onClick={() => toggleAgent(agent)}
                                className={`group flex items-center gap-1.5 pl-2 pr-2.5 py-1 rounded-full text-[11px] font-medium transition-all duration-200 border ${
                                    active
                                        ? 'border-white/10 bg-white/[0.04] hover:bg-white/[0.08]'
                                        : 'border-transparent bg-transparent opacity-35 hover:opacity-60'
                                }`}
                            >
                                <span
                                    className={`w-2.5 h-2.5 rounded-full transition-all duration-200 ${active ? 'ring-1 ring-white/20' : ''}`}
                                    style={{
                                        background: active ? color : 'transparent',
                                        borderColor: color,
                                    }}
                                />
                                <span className={active ? 'text-white/80' : 'text-white/40'}>
                                    {capitalize(agent)}
                                </span>
                                <span className={`tabular-nums ${active ? 'text-white/40' : 'text-white/20'}`}>
                                    {total.toLocaleString()}
                                </span>
                            </button>
                        )
                    })}
                </div>
            )}

            {/* Chart area */}
            <div className="px-5 pb-5" ref={chartContainerRef}>
                <AnimatePresence mode="wait">
                    {!hasData ? (
                        <motion.div
                            key="empty"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="h-52 flex items-center justify-center text-sm text-white/30"
                        >
                            {loading ? 'Loading...' : 'No trend data available yet'}
                        </motion.div>
                    ) : (
                        <motion.div
                            key="chart"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className={`h-52 relative ${loading ? 'opacity-40' : ''} transition-opacity duration-300`}
                        >
                            <ResponsiveContainer width="100%" height="100%" className="">
                                <AreaChart
                                    data={data}
                                    margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                                    onClick={handleChartClick}
                                    style={{ cursor: 'pointer' }}
                                >
                                    <defs>
                                        {!hasAgentData && (
                                            <>
                                                <linearGradient id="gradEvents" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="0%" stopColor="#64748b" stopOpacity={0.15} />
                                                    <stop offset="100%" stopColor="#64748b" stopOpacity={0} />
                                                </linearGradient>
                                                <linearGradient id="gradFindings" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="0%" stopColor="#f97316" stopOpacity={0.3} />
                                                    <stop offset="100%" stopColor="#f97316" stopOpacity={0} />
                                                </linearGradient>
                                            </>
                                        )}
                                        {hasAgentData && visibleAgents.map((agent, i) => {
                                            const color = getAgentColor(agent, i)
                                            return (
                                                <linearGradient key={agent} id={`grad-${agent}`} x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="0%" stopColor={color} stopOpacity={0.35} />
                                                    <stop offset="95%" stopColor={color} stopOpacity={0.02} />
                                                </linearGradient>
                                            )
                                        })}
                                    </defs>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                                    <XAxis
                                        dataKey="time"
                                        tickFormatter={formatTime}
                                        stroke="rgba(255,255,255,0.08)"
                                        tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }}
                                        tickLine={false}
                                        axisLine={false}
                                    />
                                    <YAxis
                                        stroke="rgba(255,255,255,0.08)"
                                        tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10 }}
                                        tickLine={false}
                                        axisLine={false}
                                        width={45}
                                        tickFormatter={(v: number) => {
                                            if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`
                                            if (v >= 1_000) return `${(v / 1_000).toFixed(0)}k`
                                            return String(v)
                                        }}
                                    />
                                    {pinnedIndex === null && (
                                        <Tooltip
                                            content={<FindingsTooltip trends={trends} />}
                                            cursor={{ stroke: 'rgba(255,255,255,0.08)', strokeWidth: 1 }}
                                        />
                                    )}
                                    {hasAgentData ? (
                                        visibleAgents.map((agent, i) => {
                                            const color = getAgentColor(agent, i)
                                            return (
                                                <Area
                                                    key={agent}
                                                    type="monotone"
                                                    dataKey={capitalize(agent)}
                                                    stackId="agents"
                                                    stroke={color}
                                                    fill={`url(#grad-${agent})`}
                                                    strokeWidth={2}
                                                    dot={false}
                                                    activeDot={{
                                                        r: 4,
                                                        fill: color,
                                                        stroke: '#0f1729',
                                                        strokeWidth: 2,
                                                    }}
                                                    animationDuration={600 + i * 150}
                                                />
                                            )
                                        })
                                    ) : (
                                        <>
                                            <Area
                                                type="monotone"
                                                dataKey="Events"
                                                stroke="#64748b"
                                                fill="url(#gradEvents)"
                                                strokeWidth={1}
                                                strokeDasharray="4 3"
                                                dot={false}
                                                activeDot={{ r: 3, fill: '#94a3b8', stroke: '#0f1729', strokeWidth: 2 }}
                                                animationDuration={1000}
                                            />
                                            <Area
                                                type="monotone"
                                                dataKey="Findings"
                                                stroke="#f97316"
                                                fill="url(#gradFindings)"
                                                strokeWidth={2}
                                                dot={false}
                                                activeDot={{ r: 4, fill: '#f97316', stroke: '#0f1729', strokeWidth: 2 }}
                                                animationDuration={1200}
                                            />
                                        </>
                                    )}
                                </AreaChart>
                            </ResponsiveContainer>

                            {/* Pinned tooltip overlay */}
                            {pinnedIndex !== null && pinnedPayload && trends[pinnedIndex] && (
                                <div
                                    className="absolute z-50 pointer-events-auto"
                                    style={{
                                        left: pinnedPos.x,
                                        top: Math.max(0, pinnedPos.y - 20),
                                        transform: pinnedPos.x > (chartContainerRef.current?.clientWidth || 400) / 2
                                            ? 'translateX(-100%)' : 'translateX(0)',
                                    }}
                                >
                                    <FindingsTooltipContent
                                        label={trends[pinnedIndex].timestamp}
                                        payload={pinnedPayload}
                                        trends={trends}
                                        pinned
                                        onClose={() => setPinnedIndex(null)}
                                    />
                                </div>
                            )}
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </motion.div>
    )
}

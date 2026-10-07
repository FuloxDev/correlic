'use client'

import { useMemo, useState, useEffect, useCallback, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { getDashboardTrends, type TrendPoint } from '@/lib/api-client'

function formatTime(ts: string): string {
    const d = new Date(ts)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#64748b',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

interface IncidentTooltipContentProps {
    label: string
    total: number
    trends: TrendPoint[]
    pinned?: boolean
    onClose?: () => void
}

function IncidentTooltipContent({ label, total, trends, pinned, onClose }: IncidentTooltipContentProps) {
    if (total === 0) return null

    const point = trends.find(p => p.timestamp === label)
    const severities = point?.incident_severities

    return (
        <div
            className="chart-tooltip-scroll backdrop-blur-xl bg-[#0f1729]/95 rounded-xl border border-white/10 shadow-2xl shadow-black/40 text-xs min-w-[160px] max-h-[240px]"
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

                {/* Total incidents */}
                <div className="flex items-center justify-between gap-4 py-0.5">
                    <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full ring-2 ring-white/10" style={{ background: '#ef4444' }} />
                        <span className="text-white/70">Incidents</span>
                    </div>
                    <span className="text-white font-medium tabular-nums">{total.toLocaleString()}</span>
                </div>

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
            </div>
        </div>
    )
}

interface IncidentTooltipProps {
    active?: boolean
    payload?: Array<{ name: string; value: number; color: string }>
    label?: string
    trends: TrendPoint[]
}

function IncidentTooltip({ active, payload, label, trends }: IncidentTooltipProps) {
    if (!active || !payload || !label) return null
    const total = payload.reduce((sum, e) => sum + (e.value || 0), 0)
    if (total === 0) return null
    return <IncidentTooltipContent label={label} total={total} trends={trends} />
}

const timeRanges = [
    { label: '30m',  points: 12, interval: 3 },
    { label: '1h',   points: 12, interval: 5 },
    { label: '2h',   points: 24, interval: 5 },
    { label: '6h',   points: 24, interval: 15 },
    { label: '24h',  points: 24, interval: 60 },
]

const DEFAULT_RANGE_IDX = 2

interface IncidentTrendChartProps {
    /** Trends data from parent — avoids duplicate API call on initial load */
    initialTrends?: TrendPoint[]
}

export default function IncidentTrendChart({ initialTrends }: IncidentTrendChartProps) {
    const [rangeIdx, setRangeIdx] = useState(DEFAULT_RANGE_IDX)
    const [trends, setTrends] = useState<TrendPoint[]>(initialTrends || [])
    const [loading, setLoading] = useState(false)
    const [pinnedIndex, setPinnedIndex] = useState<number | null>(null)
    const [pinnedPos, setPinnedPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 })
    const chartContainerRef = useRef<HTMLDivElement>(null)

    const range = timeRanges[rangeIdx]

    // Update from parent when initial data changes
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

    const totalIncidents = useMemo(() =>
        trends.reduce((sum, p) => sum + (p.incidents || 0), 0),
    [trends])

    const data = useMemo(() =>
        trends.map((p) => ({
            time: p.timestamp,
            Incidents: p.incidents || 0,
        })),
    [trends])

    const hasData = data.length > 0 && data.some((d) => d.Incidents > 0)

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handleChartClick = (state: any, event: any) => {
        if (state && state.activeTooltipIndex !== undefined) {
            const idx = state.activeTooltipIndex as number
            if (pinnedIndex === idx) {
                setPinnedIndex(null)
            } else {
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
            transition={{ delay: 0.4, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 overflow-hidden"
            style={{ borderColor: '#ef444420' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #ef44440c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px z-10" style={{ background: 'linear-gradient(90deg, transparent 10%, #ef444430, transparent 90%)' }} />
            {/* Header */}
            <div className="flex items-center justify-between px-5 pt-5 pb-3">
                <div className="flex items-center gap-3">
                    <div>
                        <h3 className="text-sm font-semibold text-white/90">Incidents Over Time</h3>
                        <p className="text-[11px] text-white/30 mt-0.5">Click chart to pin tooltip</p>
                    </div>
                    {totalIncidents > 0 && (
                        <span className="px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-[11px] font-medium text-red-400 tabular-nums">
                            {totalIncidents.toLocaleString()}
                        </span>
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

            {/* Chart area */}
            <div className="px-5 pb-5" ref={chartContainerRef}>
                <AnimatePresence mode="wait">
                    {!hasData ? (
                        <motion.div
                            key="empty"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="h-48 flex items-center justify-center text-sm text-white/30"
                        >
                            {loading ? 'Loading...' : 'No incidents in this time range'}
                        </motion.div>
                    ) : (
                        <motion.div
                            key="chart"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className={`h-48 relative ${loading ? 'opacity-40' : ''} transition-opacity duration-300`}
                        >
                            <ResponsiveContainer width="100%" height="100%" className="">
                                <AreaChart
                                    data={data}
                                    margin={{ top: 5, right: 10, left: 0, bottom: 0 }}
                                    onClick={handleChartClick}
                                    style={{ cursor: 'pointer' }}
                                >
                                    <defs>
                                        <linearGradient id="gradIncidents" x1="0" y1="0" x2="0" y2="1">
                                            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.3} />
                                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
                                        </linearGradient>
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
                                        width={35}
                                        allowDecimals={false}
                                    />
                                    {pinnedIndex === null && (
                                        <Tooltip
                                            content={<IncidentTooltip trends={trends} />}
                                            cursor={{ stroke: 'rgba(255,255,255,0.08)', strokeWidth: 1 }}
                                        />
                                    )}
                                    <Area
                                        type="monotone"
                                        dataKey="Incidents"
                                        stroke="#ef4444"
                                        fill="url(#gradIncidents)"
                                        strokeWidth={2}
                                        dot={false}
                                        activeDot={{ r: 4, fill: '#ef4444', stroke: '#0f1729', strokeWidth: 2 }}
                                        animationDuration={800}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>

                            {/* Pinned tooltip overlay */}
                            {pinnedIndex !== null && trends[pinnedIndex] && (
                                <div
                                    className="absolute z-50 pointer-events-auto"
                                    style={{
                                        left: pinnedPos.x,
                                        top: Math.max(0, pinnedPos.y - 20),
                                        transform: pinnedPos.x > (chartContainerRef.current?.clientWidth || 400) / 2
                                            ? 'translateX(-100%)' : 'translateX(0)',
                                    }}
                                >
                                    <IncidentTooltipContent
                                        label={trends[pinnedIndex].timestamp}
                                        total={trends[pinnedIndex].incidents || 0}
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

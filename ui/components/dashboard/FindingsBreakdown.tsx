'use client'

import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts'
import AnimatedNumber from './AnimatedNumber'
import type { DashboardStats } from '@/lib/api-client'

interface Props {
    stats: DashboardStats | null
}

/** Finding statuses as reported by /dashboard/stats `detection` counts. */
const STATUSES = [
    { key: 'pending', field: 'pending_findings', label: 'Pending', color: '#f97316', hint: 'Awaiting triage' },
    { key: 'investigating', field: 'investigating_findings', label: 'Investigating', color: '#eab308', hint: 'Being looked at' },
    { key: 'allowed', field: 'allowed_findings', label: 'Allowed', color: '#22c55e', hint: 'Marked as expected' },
    { key: 'auto_resolved', field: 'auto_resolved_findings', label: 'Auto-resolved', color: '#818cf8', hint: 'Closed by the engine' },
    { key: 'dismissed', field: 'dismissed_findings', label: 'Dismissed', color: '#64748b', hint: 'Closed by an analyst' },
    { key: 'suppressed', field: 'suppressed_findings', label: 'Suppressed', color: '#22d3ee', hint: 'Matched a baseline' },
] as const

type StatusKey = (typeof STATUSES)[number]['key']

export default function FindingsBreakdown({ stats }: Props) {
    const [hovered, setHovered] = useState<StatusKey | null>(null)

    const { rows, total } = useMemo(() => {
        const detection = stats?.detection
        const rows = STATUSES.map(s => ({ ...s, value: detection?.[s.field] ?? 0 }))
        const total = detection?.total_findings ?? rows.reduce((sum, r) => sum + r.value, 0)
        return { rows, total }
    }, [stats])

    const chartData = rows.filter(r => r.value > 0)
    const hoveredRow = hovered ? rows.find(r => r.key === hovered) : undefined
    const centerValue = hoveredRow ? hoveredRow.value : total

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 p-6 min-h-[400px] flex flex-col overflow-hidden"
            style={{ borderColor: '#f9731620' }}
        >
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #f973160c, transparent 70%)' }} />
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #f9731630, transparent 90%)' }} />

            <div className="relative flex items-center gap-2 mb-4">
                <h3 className="text-sm font-medium text-[var(--foreground-muted)]">Findings by Status</h3>
                {hoveredRow && (
                    <span
                        className="text-xs font-semibold px-2.5 py-0.5 rounded-full border"
                        style={{ color: hoveredRow.color, background: `${hoveredRow.color}15`, borderColor: `${hoveredRow.color}30` }}
                    >
                        {hoveredRow.label}
                    </span>
                )}
            </div>

            {!stats ? (
                <div className="relative flex-1 flex flex-col items-center justify-center gap-1">
                    <span className="text-3xl font-bold text-[var(--foreground)]">—</span>
                    <span className="text-xs text-[var(--foreground-muted)]">No data</span>
                </div>
            ) : (
                <div className="relative flex-1 flex flex-col sm:flex-row gap-6 min-h-0">
                    {/* Donut */}
                    <div className="flex flex-col items-center justify-center sm:w-[38%]">
                        <motion.div
                            initial={{ scale: 0 }}
                            animate={{ scale: 1 }}
                            transition={{ type: 'spring', stiffness: 200, damping: 20, delay: 0.7 }}
                            className="relative w-40 h-40"
                        >
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={chartData.length > 0 ? chartData : [{ key: 'none', value: 1, color: 'rgba(255,255,255,0.06)' }]}
                                        cx="50%" cy="50%"
                                        innerRadius="62%"
                                        outerRadius="88%"
                                        dataKey="value"
                                        stroke="none"
                                        animationDuration={1000}
                                        onMouseEnter={(_, index) => {
                                            const entry = chartData[index]
                                            if (entry) setHovered(entry.key)
                                        }}
                                        onMouseLeave={() => setHovered(null)}
                                        style={{ cursor: 'pointer' }}
                                    >
                                        {(chartData.length > 0 ? chartData : [{ key: 'none', color: 'rgba(255,255,255,0.06)' }]).map(entry => (
                                            <Cell
                                                key={entry.key}
                                                fill={entry.color}
                                                opacity={hovered && hovered !== entry.key ? 0.2 : 1}
                                                style={{ transition: 'opacity 0.25s ease' }}
                                            />
                                        ))}
                                    </Pie>
                                </PieChart>
                            </ResponsiveContainer>
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                                <AnimatedNumber value={centerValue} className="text-3xl font-bold text-[var(--foreground)]" />
                                <span
                                    className="text-[11px] font-medium transition-colors duration-200"
                                    style={{ color: hoveredRow ? hoveredRow.color : 'var(--foreground-muted)' }}
                                >
                                    {hoveredRow ? hoveredRow.label.toLowerCase() : 'findings'}
                                </span>
                            </div>
                        </motion.div>
                    </div>

                    <div className="hidden sm:block w-px bg-white/8 self-stretch my-2" />

                    {/* Status bars */}
                    <div className="flex-1 min-w-0 flex flex-col justify-center gap-3">
                        {rows.map((row, i) => {
                            const pct = total > 0 ? (row.value / total) * 100 : 0
                            const dimmed = hovered !== null && hovered !== row.key
                            return (
                                <motion.div
                                    key={row.key}
                                    initial={{ opacity: 0, x: 20 }}
                                    animate={{ opacity: dimmed ? 0.35 : 1, x: 0 }}
                                    transition={{ delay: 0.8 + i * 0.05, duration: 0.3 }}
                                    onMouseEnter={() => setHovered(row.key)}
                                    onMouseLeave={() => setHovered(null)}
                                    className="cursor-default"
                                >
                                    <div className="flex items-baseline justify-between mb-1">
                                        <div className="flex items-baseline gap-1.5 min-w-0">
                                            <span className="text-[11px] font-bold tracking-wide shrink-0" style={{ color: row.color }}>{row.label}</span>
                                            <span className="text-[10px] text-[var(--foreground-muted)] truncate opacity-60">{row.hint}</span>
                                        </div>
                                        <span className="text-[11px] font-semibold tabular-nums ml-2 shrink-0 text-[var(--foreground-muted)]">
                                            {row.value.toLocaleString()}
                                            <span className="opacity-60"> · {pct.toFixed(0)}%</span>
                                        </span>
                                    </div>
                                    <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: `${pct}%` }}
                                            transition={{ delay: 0.9 + i * 0.05, duration: 0.8, ease: 'easeOut' }}
                                            className="h-full rounded-full"
                                            style={{ background: row.color }}
                                        />
                                    </div>
                                </motion.div>
                            )
                        })}
                    </div>
                </div>
            )}
        </motion.div>
    )
}

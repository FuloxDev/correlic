'use client'

import { motion } from 'framer-motion'
import { ShieldCheck, Filter, Database } from 'lucide-react'
import { AreaChart, Area, ResponsiveContainer } from 'recharts'
import AnimatedNumber from './AnimatedNumber'
import type { DashboardStats } from '@/lib/api-client'

interface Props {
    stats: DashboardStats | null
}

interface ProgressBarProps {
    label: string
    icon: React.ReactNode
    value: number
    maxValue: number
    color: string
    format?: (v: number) => string
    sparkData?: { value: number }[]
    sparkColor?: string
    delay: number
}

function ProgressBar({ label, icon, value, maxValue, color, format, sparkData, sparkColor, delay }: ProgressBarProps) {
    const percent = maxValue > 0 ? Math.min(100, (value / maxValue) * 100) : 0

    return (
        <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay, duration: 0.4 }}
            className="space-y-2"
        >
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm">
                    <span className="text-[var(--foreground-muted)]">{icon}</span>
                    <span className="text-[var(--foreground-muted)]">{label}</span>
                </div>
                <div className="flex items-center gap-2">
                    {sparkData && sparkData.length > 1 && (
                        <div className="w-16 h-5">
                            <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={sparkData}>
                                    <Area
                                        type="monotone"
                                        dataKey="value"
                                        stroke={sparkColor || color}
                                        fill={sparkColor || color}
                                        fillOpacity={0.1}
                                        strokeWidth={1}
                                        dot={false}
                                        isAnimationActive={false}
                                    />
                                </AreaChart>
                            </ResponsiveContainer>
                        </div>
                    )}
                    <AnimatedNumber
                        value={value}
                        className="text-sm font-bold text-[var(--foreground)]"
                        format={format || ((n) => Math.round(n).toLocaleString())}
                    />
                </div>
            </div>
            <div className="h-2 bg-white/[0.06] rounded-full overflow-hidden">
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${percent}%` }}
                    transition={{ delay: delay + 0.2, duration: 1, ease: 'easeOut' }}
                    className="h-full rounded-full"
                    style={{ background: color }}
                />
            </div>
        </motion.div>
    )
}

export default function DetectionHealth({ stats }: Props) {
    const totalFindings = stats?.detection?.total_findings ?? 0
    const pendingFindings = stats?.detection?.pending_findings ?? 0
    const resolvedFindings = (stats?.detection?.allowed_findings ?? 0)
        + (stats?.detection?.dismissed_findings ?? 0)
        + (stats?.detection?.auto_resolved_findings ?? 0)
    const resolutionRate = totalFindings > 0 ? (resolvedFindings / totalFindings) * 100 : 0
    const suppressionRate = stats?.detection?.suppression_rate ?? 0
    const baselines = stats?.detection?.total_baselines ?? 0

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 p-5 h-[400px] flex flex-col overflow-hidden"
            style={{ borderColor: '#8b5cf620' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #8b5cf60c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #8b5cf630, transparent 90%)' }} />

            <h3 className="relative text-sm font-medium text-[var(--foreground-muted)] mb-4">Detection Health</h3>

            <div className="relative flex-1 flex flex-col justify-center space-y-6">
                <ProgressBar
                    label="Resolution Rate"
                    icon={<ShieldCheck className="w-4 h-4" />}
                    value={resolutionRate}
                    maxValue={100}
                    color="#22c55e"
                    format={(n) => `${n.toFixed(1)}%`}
                    delay={1.0}
                />

                <ProgressBar
                    label="Suppression Rate"
                    icon={<Filter className="w-4 h-4" />}
                    value={suppressionRate}
                    maxValue={100}
                    color="#8b5cf6"
                    format={(n) => `${n.toFixed(1)}%`}
                    delay={1.1}
                />

                <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 1.2, duration: 0.4 }}
                    className="flex items-center justify-between rounded-2xl p-4 border"
                    style={{ background: 'linear-gradient(to bottom, #a855f70c, #a855f704)', borderColor: '#a855f725' }}
                >
                    <div className="flex items-center gap-2">
                        <div className="p-1 rounded-lg" style={{ background: '#a855f715' }}>
                            <Database className="w-4 h-4 text-purple-400" />
                        </div>
                        <span className="text-sm text-[var(--foreground-muted)]">Baselines Learned</span>
                    </div>
                    <AnimatedNumber
                        value={baselines}
                        className="text-xl font-bold text-[var(--foreground)]"
                    />
                </motion.div>

                {/* Quick stats row */}
                <div className="grid grid-cols-2 gap-3">
                    <div className="text-center rounded-2xl p-2 border" style={{ background: 'linear-gradient(to bottom, #f973160c, #f9731604)', borderColor: '#f9731625' }}>
                        <AnimatedNumber
                            value={pendingFindings}
                            className="text-lg font-bold text-[var(--high)]"
                        />
                        <div className="text-xs text-[var(--foreground-muted)]">Pending</div>
                    </div>
                    <div className="text-center rounded-2xl p-2 border" style={{ background: 'linear-gradient(to bottom, #22c55e0c, #22c55e04)', borderColor: '#22c55e25' }}>
                        <AnimatedNumber
                            value={totalFindings}
                            className="text-lg font-bold text-[var(--foreground)]"
                        />
                        <div className="text-xs text-[var(--foreground-muted)]">Total</div>
                    </div>
                </div>
            </div>
        </motion.div>
    )
}

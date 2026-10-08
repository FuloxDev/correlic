'use client'

import { motion } from 'framer-motion'
import { Link2, Clock, ChevronRight } from 'lucide-react'
import Link from 'next/link'
import type { Incident } from '@/lib/api-client'

interface Props {
    incidents: Incident[]
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#f43f5e',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
}

const SEVERITY_BG: Record<string, string> = {
    critical: 'bg-[var(--critical)]/10',
    high: 'bg-[var(--high)]/10',
    medium: 'bg-[var(--medium)]/10',
    low: 'bg-[var(--low)]/10',
}

function formatTimeAgo(ts: string): string {
    const diff = Date.now() - new Date(ts).getTime()
    const secs = Math.floor(diff / 1000)
    if (secs < 60) return `${secs}s ago`
    const mins = Math.floor(secs / 60)
    if (mins < 60) return `${mins}m ago`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `${hrs}h ago`
    return `${Math.floor(hrs / 24)}d ago`
}

const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
        opacity: 1,
        transition: { staggerChildren: 0.08, delayChildren: 0.6 },
    },
}

const itemVariants = {
    hidden: { opacity: 0, x: -30 },
    visible: { opacity: 1, x: 0, transition: { duration: 0.4 } },
}

export default function RecentIncidents({ incidents }: Props) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 p-5 h-[400px] flex flex-col overflow-hidden"
            style={{ borderColor: '#f43f5e20' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #f43f5e0c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #f43f5e30, transparent 90%)' }} />

            <div className="relative flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium text-[var(--foreground-muted)]">Recent Incidents</h3>
                <Link
                    href="/incidents"
                    className="text-xs text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors flex items-center gap-1"
                >
                    View all <ChevronRight className="w-3 h-3" />
                </Link>
            </div>

            {incidents.length === 0 ? (
                <div className="flex-1 flex items-center justify-center text-sm text-[var(--foreground-muted)]">
                    No open incidents
                </div>
            ) : (
                <motion.div
                    variants={containerVariants}
                    initial="hidden"
                    animate="visible"
                    className="flex-1 overflow-y-auto space-y-2 scrollbar-thin"
                >
                    {incidents.map((inc) => (
                        <motion.div key={inc.id} variants={itemVariants} whileHover={{ scale: 1.01 }}>
                            <Link
                                href={`/incidents/${inc.id}`}
                                className="flex items-stretch gap-3 bg-[#0d1117]/60 border border-white/[0.07] rounded-2xl p-3 transition-all group"
                            >
                                {/* Severity bar */}
                                <div
                                    className="w-1 rounded-full shrink-0"
                                    style={{ background: SEVERITY_COLORS[inc.severity] || SEVERITY_COLORS.low }}
                                />
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 mb-1">
                                        <span
                                            className={`text-[10px] font-medium uppercase px-1.5 py-0.5 rounded ${SEVERITY_BG[inc.severity] || ''}`}
                                            style={{ color: SEVERITY_COLORS[inc.severity] }}
                                        >
                                            {inc.severity}
                                        </span>
                                        {inc.chain_finding_id && (
                                            <span className="text-[10px] text-[var(--accent)] flex items-center gap-0.5">
                                                <Link2 className="w-3 h-3" /> chain
                                            </span>
                                        )}
                                        <span className="text-[10px] text-[var(--foreground-muted)] ml-auto flex items-center gap-1">
                                            <Clock className="w-3 h-3" />
                                            {formatTimeAgo(inc.created_at)}
                                        </span>
                                    </div>
                                    <div className="text-sm text-[var(--foreground)] truncate group-hover:text-[var(--accent)] transition-colors">
                                        {inc.title}
                                    </div>
                                    <div className="flex items-center gap-2 mt-1.5">
                                        <span className="text-xs text-[var(--foreground-muted)]">
                                            {inc.finding_ids?.length || 0} findings
                                        </span>
                                        {inc.mitre_techniques?.slice(0, 3).map((t) => (
                                            <span
                                                key={t}
                                                className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-[var(--foreground-muted)]"
                                            >
                                                {t}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                                <ChevronRight className="w-4 h-4 text-[var(--foreground-muted)] self-center opacity-0 group-hover:opacity-100 transition-opacity" />
                            </Link>
                        </motion.div>
                    ))}
                </motion.div>
            )}
        </motion.div>
    )
}

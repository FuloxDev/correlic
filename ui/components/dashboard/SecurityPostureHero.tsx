'use client'

import { motion } from 'framer-motion'
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts'
import {
    Shield, AlertTriangle, Bug, Activity, Database,
    Search, CheckCircle, XCircle, EyeOff, Cpu, FileText, Globe, Wifi, LogOut,
} from 'lucide-react'
import AnimatedNumber from './AnimatedNumber'
import type { DashboardStats, TrendPoint } from '@/lib/api-client'

interface Props {
    stats: DashboardStats | null
    trends: TrendPoint[]
}

function computePostureScore(stats: DashboardStats | null): number {
    if (!stats) return 100

    const criticalOpen = stats.incidents?.critical_open ?? 0
    const pendingFindings = stats.detection?.pending_findings ?? 0
    const totalFindings = stats.detection?.total_findings ?? 0
    const openIncidents = (stats.incidents?.open ?? 0) + (stats.incidents?.investigating ?? 0)
    const totalIncidents = stats.incidents?.total ?? 0

    // Resolution ratios — reward resolved work (0 = all open, 1 = all resolved)
    const findingResolutionRate = totalFindings > 0 ? 1 - (pendingFindings / totalFindings) : 1
    const incidentResolutionRate = totalIncidents > 0 ? 1 - (openIncidents / totalIncidents) : 1

    // Critical incidents: steep penalty, but capped at 30. Each one costs ~10pts diminishing.
    const criticalPenalty = criticalOpen > 0 ? Math.min(30, 10 * Math.sqrt(criticalOpen)) : 0

    // Open incidents: penalty scaled down by resolution rate. More resolved = less penalty.
    // 6 open out of 53 total → ratio 0.89 → penalty * 0.11 → small.
    const rawIncidentPenalty = openIncidents > 0 ? Math.min(25, 8 * Math.sqrt(openIncidents)) : 0
    const incidentPenalty = rawIncidentPenalty * (1 - incidentResolutionRate * 0.7)

    // Pending findings: penalty scaled down by resolution rate.
    // 45 pending out of 369 → ratio 0.88 → penalty * 0.12 → small.
    const rawFindingsPenalty = pendingFindings > 0 ? Math.min(25, 4 * Math.sqrt(pendingFindings)) : 0
    const findingsPenalty = rawFindingsPenalty * (1 - findingResolutionRate * 0.7)

    return Math.max(0, Math.min(100, Math.round(100 - criticalPenalty - incidentPenalty - findingsPenalty)))
}

function postureColor(score: number): string {
    if (score >= 80) return '#22c55e'
    if (score >= 50) return '#eab308'
    if (score >= 25) return '#f97316'
    return '#f43f5e'
}

function postureLabel(score: number): string {
    if (score >= 80) return 'Healthy'
    if (score >= 50) return 'Elevated'
    if (score >= 25) return 'High Risk'
    return 'Critical'
}

// Segmented bar component for showing status breakdowns
interface Segment {
    value: number
    color: string
    label: string
}

function SegmentedBar({ segments, total }: { segments: Segment[]; total: number }) {
    if (total === 0) return <div className="h-2 bg-white/[0.06] rounded-full" />
    return (
        <div className="h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
            {segments.map((seg, i) => {
                const pct = (seg.value / total) * 100
                if (pct === 0) return null
                return (
                    <motion.div
                        key={i}
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ delay: 0.6 + i * 0.1, duration: 0.8, ease: 'easeOut' }}
                        className="h-full"
                        style={{ background: seg.color }}
                    />
                )
            })}
        </div>
    )
}

// Sub-stat row
function SubStat({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color: string }) {
    return (
        <div className="flex items-center gap-1.5">
            <span style={{ color }}>{icon}</span>
            <span className="text-[10px] text-gray-400">{label}</span>
            <span className="text-xs font-semibold text-[var(--foreground)]">{value.toLocaleString()}</span>
        </div>
    )
}

const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i: number) => ({
        opacity: 1,
        y: 0,
        transition: { delay: 0.3 + i * 0.12, duration: 0.5 },
    }),
}

interface StatCardConfig {
    label: string
    icon: typeof AlertTriangle
    hex: string
    color: string
}

const statCardConfigs: StatCardConfig[] = [
    { label: 'Findings', icon: AlertTriangle, hex: '#f97316', color: 'text-orange-400' },
    { label: 'Incidents', icon: Bug, hex: '#f43f5e', color: 'text-rose-400' },
    { label: 'Events', icon: Activity, hex: '#06b6d4', color: 'text-cyan-400' },
    { label: 'Baselines', icon: Database, hex: '#a855f7', color: 'text-purple-400' },
]

export default function SecurityPostureHero({ stats }: Props) {
    const score = computePostureScore(stats)
    const color = postureColor(score)
    const gaugeData = [{ value: score, fill: color }]

    // Findings breakdown
    const pending = stats?.detection?.pending_findings ?? 0
    const allowed = stats?.detection?.allowed_findings ?? 0
    const dismissed = stats?.detection?.dismissed_findings ?? 0
    const autoResolved = stats?.detection?.auto_resolved_findings ?? 0
    const investigating = stats?.detection?.investigating_findings ?? 0
    const suppressed = stats?.detection?.suppressed_findings ?? 0
    const totalFindings = stats?.detection?.total_findings ?? 0
    const resolved = allowed + dismissed + autoResolved

    // Incidents breakdown
    const incOpen = stats?.incidents?.open ?? 0
    const incInvestigating = stats?.incidents?.investigating ?? 0
    const incResolved = stats?.incidents?.resolved ?? 0
    const incDismissed = stats?.incidents?.dismissed ?? 0
    const incAutoResolved = stats?.incidents?.auto_resolved ?? 0
    const incTotal = stats?.incidents?.total ?? 0

    // Events breakdown
    const evtExec = stats?.events?.process_exec ?? 0
    const evtFile = stats?.events?.file_open ?? 0
    const evtNet = stats?.events?.net_connect ?? 0
    const evtDns = stats?.events?.net_dns ?? 0
    const evtExit = stats?.events?.process_exit ?? 0
    const evtTotal = evtExec + evtFile + evtNet + evtDns + evtExit

    // Baselines breakdown
    const autoBaselines = stats?.detection?.auto_baselines ?? 0
    const manualBaselines = stats?.detection?.manual_baselines ?? 0
    const totalBaselines = stats?.detection?.total_baselines ?? 0

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="bg-[#0d1117]/80 border-2 border-white/[0.07] rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 p-6"
            style={{ borderTopColor: color, borderTopWidth: 3 }}
        >
            <div className="flex flex-col lg:flex-row items-center gap-6">
                {/* Radial gauge */}
                <div className="flex flex-col items-center gap-1 shrink-0">
                    <motion.div
                        initial={{ scale: 0, rotate: -180 }}
                        animate={{ scale: 1, rotate: 0 }}
                        transition={{ type: 'spring', stiffness: 100, damping: 20, duration: 1.2 }}
                        className="relative w-36 h-36"
                    >
                        <ResponsiveContainer width="100%" height="100%">
                            <RadialBarChart
                                cx="50%" cy="50%"
                                innerRadius="70%" outerRadius="100%"
                                barSize={10}
                                data={gaugeData}
                                startAngle={210}
                                endAngle={-30}
                            >
                                <RadialBar
                                    dataKey="value"
                                    cornerRadius={6}
                                    background={{ fill: 'rgba(255,255,255,0.05)' }}
                                    isAnimationActive={true}
                                    animationDuration={1500}
                                />
                            </RadialBarChart>
                        </ResponsiveContainer>
                        <div className="absolute inset-0 flex flex-col items-center justify-center">
                            <AnimatedNumber
                                value={score}
                                className="text-3xl font-bold"
                                format={(n) => Math.round(n).toString()}
                            />
                            <span className="text-xs text-[var(--foreground-muted)]">/ 100</span>
                        </div>
                    </motion.div>
                    <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4" style={{ color }} />
                        <span className="text-sm font-medium" style={{ color }}>{postureLabel(score)}</span>
                    </div>
                </div>

                {/* Stat cards grid */}
                <div className="flex-1 grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 w-full">
                    {statCardConfigs.map((cfg, idx) => {
                        const CardIcon = cfg.icon
                        const cardData = [
                            // Findings
                            { total: totalFindings, segments: [
                                { value: pending, color: '#f97316', label: 'Pending' },
                                { value: investigating, color: '#eab308', label: 'Investigating' },
                                { value: allowed, color: '#22c55e', label: 'Allowed' },
                                { value: autoResolved, color: '#818cf8', label: 'Auto-resolved' },
                                { value: dismissed, color: '#64748b', label: 'Dismissed' },
                                { value: suppressed, color: '#22d3ee', label: 'Suppressed' },
                            ], subs: (
                                <>
                                    <SubStat icon={<Search className="w-3 h-3" />} label="Pending" value={pending} color="#f97316" />
                                    <SubStat icon={<CheckCircle className="w-3 h-3" />} label="Resolved" value={resolved} color="#22c55e" />
                                    <SubStat icon={<EyeOff className="w-3 h-3" />} label="Suppressed" value={suppressed} color="#22d3ee" />
                                </>
                            )},
                            // Incidents
                            { total: incTotal, segments: [
                                { value: incOpen, color: '#f43f5e', label: 'Open' },
                                { value: incInvestigating, color: '#eab308', label: 'Investigating' },
                                { value: incResolved, color: '#22c55e', label: 'Resolved' },
                                { value: incAutoResolved, color: '#818cf8', label: 'Auto-resolved' },
                                { value: incDismissed, color: '#64748b', label: 'Dismissed' },
                            ], subs: (
                                <>
                                    <SubStat icon={<AlertTriangle className="w-3 h-3" />} label="Open" value={incOpen + incInvestigating} color="#f43f5e" />
                                    <SubStat icon={<CheckCircle className="w-3 h-3" />} label="Resolved" value={incResolved + incAutoResolved} color="#22c55e" />
                                    <SubStat icon={<XCircle className="w-3 h-3" />} label="Dismissed" value={incDismissed} color="#64748b" />
                                </>
                            )},
                            // Events
                            { total: evtTotal, segments: [
                                { value: evtExec, color: '#f97316', label: 'Exec' },
                                { value: evtFile, color: '#22d3ee', label: 'File' },
                                { value: evtNet, color: '#818cf8', label: 'Network' },
                                { value: evtDns, color: '#a78bfa', label: 'DNS' },
                                { value: evtExit, color: '#64748b', label: 'Exit' },
                            ], subs: (
                                <>
                                    <SubStat icon={<Cpu className="w-3 h-3" />} label="Exec" value={evtExec} color="#f97316" />
                                    <SubStat icon={<FileText className="w-3 h-3" />} label="File" value={evtFile} color="#22d3ee" />
                                    <SubStat icon={<Wifi className="w-3 h-3" />} label="Net" value={evtNet} color="#818cf8" />
                                    <SubStat icon={<Globe className="w-3 h-3" />} label="DNS" value={evtDns} color="#a78bfa" />
                                    <SubStat icon={<LogOut className="w-3 h-3" />} label="Exit" value={evtExit} color="#64748b" />
                                </>
                            )},
                            // Baselines
                            { total: totalBaselines, segments: [
                                { value: autoBaselines, color: '#818cf8', label: 'Auto-learned' },
                                { value: manualBaselines, color: '#22c55e', label: 'User confirmed' },
                            ], subs: (
                                <>
                                    <SubStat icon={<Cpu className="w-3 h-3" />} label="Auto" value={autoBaselines} color="#818cf8" />
                                    <SubStat icon={<CheckCircle className="w-3 h-3" />} label="Manual" value={manualBaselines} color="#22c55e" />
                                </>
                            )},
                        ][idx]

                        return (
                            <motion.div
                                key={cfg.label}
                                custom={idx}
                                variants={cardVariants}
                                initial="hidden"
                                animate="visible"
                                whileHover={{ scale: 1.03, y: -2 }}
                                whileTap={{ scale: 0.97 }}
                                className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                                style={{
                                    background: `linear-gradient(to bottom, ${cfg.hex}0c, ${cfg.hex}04)`,
                                    borderColor: `${cfg.hex}30`,
                                }}
                            >
                                {/* Radial glow */}
                                <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(circle at 50% 0%, ${cfg.hex}0c, transparent 70%)` }} />
                                {/* Top edge highlight */}
                                <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 10%, ${cfg.hex}30, transparent 90%)` }} />

                                <div className="relative flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <div className="p-1.5 rounded-xl" style={{ background: `${cfg.hex}15` }}>
                                            <CardIcon className={`w-4 h-4 ${cfg.color}`} />
                                        </div>
                                        <span className={`text-xs font-semibold ${cfg.color} opacity-70`}>{cfg.label}</span>
                                    </div>
                                    <AnimatedNumber value={cardData.total} className="text-2xl font-extrabold text-[var(--foreground)]" />
                                </div>
                                <div className="relative">
                                    <SegmentedBar total={cardData.total} segments={cardData.segments} />
                                </div>
                                <div className="relative flex flex-wrap gap-x-3 gap-y-1">
                                    {cardData.subs}
                                </div>
                            </motion.div>
                        )
                    })}
                </div>
            </div>
        </motion.div>
    )
}

'use client'

import { useState, useMemo, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
    PieChart, Pie, Cell, ResponsiveContainer,
} from 'recharts'
import AnimatedNumber from './AnimatedNumber'
import type { Finding } from '@/lib/api-client'

interface Props {
    findings: Finding[]
}

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#f43f5e',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

const MITRE_NAMES: Record<string, string> = {
    T1552: 'Credentials in Files',
    'T1552.004': 'Private Keys',
    T1041: 'Exfil Over C2',
    T1567: 'Exfil Over Web Service',
    T1059: 'Command Execution',
    'T1059.004': 'Unix Shell',
    T1071: 'App Layer Protocol',
    T1571: 'Non-Standard Port',
    T1568: 'Dynamic Resolution',
    'T1071.004': 'DNS Protocol',
    T1546: 'Event-Triggered Exec',
    T1053: 'Scheduled Task/Job',
    'T1098.004': 'SSH Authorized Keys',
    T1543: 'Create System Process',
    T1548: 'Abuse Elevation Control',
    'T1548.003': 'Sudo/Doas Abuse',
    T1068: 'Exploitation for Priv Esc',
    T1611: 'Escape to Host',
    'T1195.002': 'Supply Chain: Software',
    T1554: 'Compromise Binary',
    'T1059.006': 'Python',
    T1485: 'Data Destruction',
    T1486: 'Data Encrypted for Impact',
    T1021: 'Remote Services',
    'T1055.008': 'Ptrace Injection',
    'T1556.003': 'Pluggable Auth Modules',
    'T1574.006': 'LD_PRELOAD Hijacking',
    'T1547.001': 'Boot Autostart Exec',
    T1074: 'Data Staging',
    T1610: 'Deploy Container',
    T1613: 'Container Discovery',
    T1082: 'System Info Discovery',
    T1083: 'File & Dir Discovery',
    T1057: 'Process Discovery',
    T1016: 'System Network Config',
    T1049: 'System Network Connections',
    T1033: 'System Owner Discovery',
}

interface MitreEntry {
    technique: string
    fullName: string
    total: number
    critical: number
    high: number
    medium: number
    low: number
}

function MitreBar({ entry, hoveredSeverity, labelColor, index }: {
    entry: MitreEntry
    hoveredSeverity: string | null
    labelColor: string
    index: number
}) {
    const [hovered, setHovered] = useState(false)
    const total = entry.total

    const segments = hoveredSeverity
        ? [{ sev: hoveredSeverity, count: entry[hoveredSeverity as keyof MitreEntry] as number, pct: 100 }]
        : SEVERITY_ORDER
            .filter((sev) => (entry[sev as keyof MitreEntry] as number) > 0)
            .map((sev) => ({
                sev,
                count: entry[sev as keyof MitreEntry] as number,
                pct: ((entry[sev as keyof MitreEntry] as number) / total) * 100,
            }))

    const displayCount = hoveredSeverity ? (entry[hoveredSeverity as keyof MitreEntry] as number) : total

    return (
        <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.8 + index * 0.06, duration: 0.4 }}
            className="relative"
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
        >
            {/* Label row: technique ID + full name */}
            <div className="flex items-baseline justify-between mb-1">
                <div className="flex items-baseline gap-1.5 min-w-0">
                    <span
                        className="text-[11px] font-bold tracking-wide shrink-0"
                        style={{ color: labelColor }}
                    >
                        {entry.technique}
                    </span>
                    <span className="text-[10px] text-[var(--foreground-muted)] truncate opacity-60">
                        {entry.fullName}
                    </span>
                </div>
                <span
                    className="text-[11px] font-semibold tabular-nums ml-2 shrink-0"
                    style={{ color: hoveredSeverity ? SEVERITY_COLORS[hoveredSeverity] : 'var(--foreground-muted)' }}
                >
                    {displayCount}
                </span>
            </div>

            {/* Proportional bar */}
            <div
                className="flex h-2 rounded-full overflow-hidden transition-all duration-200"
                style={{
                    background: 'rgba(255,255,255,0.04)',
                    boxShadow: hovered ? `0 0 12px ${labelColor}20` : 'none',
                }}
            >
                {segments.map((seg, i) => (
                    <motion.div
                        key={seg.sev}
                        initial={{ width: 0 }}
                        animate={{ width: `${seg.pct}%` }}
                        transition={{ duration: 0.6, delay: 0.9 + index * 0.06, ease: [0.16, 1, 0.3, 1] }}
                        className="h-full transition-opacity duration-200"
                        style={{
                            backgroundColor: SEVERITY_COLORS[seg.sev],
                            opacity: hovered ? 1 : 0.85,
                            borderRadius: i === 0 && i === segments.length - 1
                                ? '9999px'
                                : i === 0
                                    ? '9999px 0 0 9999px'
                                    : i === segments.length - 1
                                        ? '0 9999px 9999px 0'
                                        : '0',
                        }}
                    />
                ))}
            </div>

            {/* Tooltip */}
            <AnimatePresence>
                {hovered && !hoveredSeverity && (
                    <motion.div
                        initial={{ opacity: 0, y: 6, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        exit={{ opacity: 0, y: 6, scale: 0.95 }}
                        transition={{ duration: 0.15 }}
                        className="absolute left-0 top-full mt-1 z-50 glass-effect rounded-lg px-3 py-2.5 border border-white/15 text-xs pointer-events-none shadow-xl shadow-black/30"
                        style={{ minWidth: 180 }}
                    >
                        <div className="text-[var(--foreground)] font-semibold">{entry.fullName}</div>
                        <div className="text-[var(--foreground-muted)] mt-0.5">{entry.technique} — {total} total</div>
                        <div className="flex gap-3 mt-1.5 pt-1.5 border-t border-white/10">
                            {entry.critical > 0 && (
                                <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEVERITY_COLORS.critical }} />
                                    <span style={{ color: SEVERITY_COLORS.critical }}>{entry.critical}</span>
                                </span>
                            )}
                            {entry.high > 0 && (
                                <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEVERITY_COLORS.high }} />
                                    <span style={{ color: SEVERITY_COLORS.high }}>{entry.high}</span>
                                </span>
                            )}
                            {entry.medium > 0 && (
                                <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEVERITY_COLORS.medium }} />
                                    <span style={{ color: SEVERITY_COLORS.medium }}>{entry.medium}</span>
                                </span>
                            )}
                            {entry.low > 0 && (
                                <span className="flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEVERITY_COLORS.low }} />
                                    <span style={{ color: SEVERITY_COLORS.low }}>{entry.low}</span>
                                </span>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    )
}

export default function SeverityBreakdown({ findings }: Props) {
    const [hoveredSeverity, setHoveredSeverity] = useState<string | null>(null)

    const { severityData, totalFindings, mitreData } = useMemo(() => {
        const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
        const mitreMap: Record<string, { total: number; critical: number; high: number; medium: number; low: number }> = {}

        for (const f of findings) {
            const sev = f.severity?.toLowerCase() || 'low'
            counts[sev] = (counts[sev] || 0) + 1

            // Exclude low-severity findings from MITRE breakdown — they add noise
            // without investigative value (e.g. routine AI command activity).
            if (sev !== 'low') {
                // JSONB round-trip can deliver either a real array or a JSON-encoded string
                const raw = f.context?.mitre_techniques as unknown
                let techniques: string[] | undefined
                if (Array.isArray(raw)) {
                    techniques = raw as string[]
                } else if (typeof raw === 'string' && raw.trim().startsWith('[')) {
                    try { techniques = JSON.parse(raw) } catch { techniques = undefined }
                }

                if (techniques && techniques.length > 0) {
                    for (const t of techniques) {
                        if (!mitreMap[t]) {
                            mitreMap[t] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }
                        }
                        mitreMap[t].total++
                        if (sev === 'critical') mitreMap[t].critical++
                        else if (sev === 'high') mitreMap[t].high++
                        else if (sev === 'medium') mitreMap[t].medium++
                    }
                }
            }
        }

        const severityData = SEVERITY_ORDER
            .filter((sev) => sev !== 'low')
            .map((sev) => ({ name: sev, value: counts[sev] || 0, color: SEVERITY_COLORS[sev] }))
            .filter((d) => d.value > 0)

        const mitreData: MitreEntry[] = Object.entries(mitreMap)
            .sort((a, b) => b[1].total - a[1].total)
            .slice(0, 7)
            .map(([t, data]) => ({
                technique: t,
                fullName: MITRE_NAMES[t] || t,
                ...data,
            }))

        const totalFindings = (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0)
        return { severityData, totalFindings, mitreData }
    }, [findings])

    const filteredMitreData = useMemo(() => {
        if (!hoveredSeverity) return mitreData
        const sev = hoveredSeverity as keyof MitreEntry
        return mitreData
            .filter((d) => (d[sev] as number) > 0)
            .sort((a, b) => (b[sev] as number) - (a[sev] as number))
    }, [mitreData, hoveredSeverity])

    function labelColor(entry: MitreEntry): string {
        if (hoveredSeverity) return SEVERITY_COLORS[hoveredSeverity]
        if (entry.critical > 0) return SEVERITY_COLORS.critical
        if (entry.high > 0) return SEVERITY_COLORS.high
        if (entry.medium > 0) return SEVERITY_COLORS.medium
        return SEVERITY_COLORS.low
    }

    const onPieEnter = useCallback((_: unknown, index: number) => {
        const entry = severityData[index]
        if (entry) setHoveredSeverity(entry.name)
    }, [severityData])

    const onPieLeave = useCallback(() => {
        setHoveredSeverity(null)
    }, [])

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6, duration: 0.5 }}
            className="relative bg-[#0d1117]/80 border-2 rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 p-6 h-[400px] flex flex-col overflow-hidden"
            style={{ borderColor: '#f9731620' }}
        >
            {/* Radial glow */}
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #f973160c, transparent 70%)' }} />
            {/* Top edge highlight */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #f9731630, transparent 90%)' }} />

            <div className="relative flex items-center gap-2 mb-4">
                <h3 className="text-sm font-medium text-[var(--foreground-muted)]">Severity & MITRE Breakdown</h3>
                <AnimatePresence>
                    {hoveredSeverity && (
                        <motion.span
                            initial={{ opacity: 0, x: -8, scale: 0.9 }}
                            animate={{ opacity: 1, x: 0, scale: 1 }}
                            exit={{ opacity: 0, x: -8, scale: 0.9 }}
                            className="text-xs font-semibold capitalize px-2.5 py-0.5 rounded-full border"
                            style={{
                                color: SEVERITY_COLORS[hoveredSeverity],
                                background: `${SEVERITY_COLORS[hoveredSeverity]}15`,
                                borderColor: `${SEVERITY_COLORS[hoveredSeverity]}30`,
                            }}
                        >
                            {hoveredSeverity} only
                        </motion.span>
                    )}
                </AnimatePresence>
            </div>

            <div className="flex-1 flex gap-6 min-h-0">
                {/* Donut chart */}
                <div className="flex flex-col items-center justify-center w-[35%]">
                    <motion.div
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        transition={{ type: 'spring', stiffness: 200, damping: 20, delay: 0.7 }}
                        className="relative w-40 h-40"
                    >
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={severityData.length > 0 ? severityData : [{ name: 'none', value: 1, color: 'rgba(255,255,255,0.06)' }]}
                                    cx="50%" cy="50%"
                                    innerRadius="62%"
                                    outerRadius="88%"
                                    dataKey="value"
                                    stroke="none"
                                    animationDuration={1000}
                                    onMouseEnter={onPieEnter}
                                    onMouseLeave={onPieLeave}
                                    style={{ cursor: 'pointer' }}
                                >
                                    {(severityData.length > 0 ? severityData : [{ name: 'none', color: 'rgba(255,255,255,0.06)' }]).map((entry, i) => (
                                        <Cell
                                            key={i}
                                            fill={entry.color}
                                            opacity={hoveredSeverity && hoveredSeverity !== entry.name ? 0.2 : 1}
                                            style={{ transition: 'opacity 0.25s ease', filter: hoveredSeverity === entry.name ? `drop-shadow(0 0 6px ${entry.color}60)` : 'none' }}
                                        />
                                    ))}
                                </Pie>
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                            <AnimatedNumber
                                value={hoveredSeverity
                                    ? (severityData.find((d) => d.name === hoveredSeverity)?.value || 0)
                                    : totalFindings}
                                className="text-3xl font-bold text-[var(--foreground)]"
                            />
                            <span
                                className="text-[11px] font-medium capitalize transition-colors duration-200"
                                style={{ color: hoveredSeverity ? SEVERITY_COLORS[hoveredSeverity] : 'var(--foreground-muted)' }}
                            >
                                {hoveredSeverity || 'findings'}
                            </span>
                        </div>
                    </motion.div>

                    {/* Legend */}
                    <div className="flex flex-wrap justify-center gap-x-3 gap-y-1.5 mt-4">
                        {SEVERITY_ORDER.filter((s) => s !== 'low').map((sev) => {
                            const d = severityData.find((s) => s.name === sev)
                            const dimmed = hoveredSeverity && hoveredSeverity !== sev
                            const active = hoveredSeverity === sev
                            return (
                                <div
                                    key={sev}
                                    className="flex items-center gap-1 text-xs cursor-pointer transition-all duration-200"
                                    style={{ opacity: dimmed ? 0.25 : 1, transform: active ? 'scale(1.05)' : 'scale(1)' }}
                                    onMouseEnter={() => setHoveredSeverity(sev)}
                                    onMouseLeave={() => setHoveredSeverity(null)}
                                >
                                    <span
                                        className="w-2 h-2 rounded-full transition-shadow duration-200"
                                        style={{
                                            background: SEVERITY_COLORS[sev],
                                            boxShadow: active ? `0 0 6px ${SEVERITY_COLORS[sev]}80` : 'none',
                                        }}
                                    />
                                    <span className="text-[var(--foreground-muted)] capitalize">{sev}</span>
                                    <span className="font-bold tabular-nums" style={{ color: SEVERITY_COLORS[sev] }}>{d?.value || 0}</span>
                                </div>
                            )
                        })}
                    </div>
                </div>

                {/* Divider */}
                <div className="w-px bg-white/8 self-stretch my-2" />

                {/* MITRE proportional bars */}
                <div className="flex-1 min-w-0 flex flex-col">
                    <div className="text-[11px] font-medium tracking-wider uppercase text-[var(--foreground-muted)] mb-3 opacity-60">
                        Top MITRE ATT&CK Techniques
                    </div>
                    {filteredMitreData.length === 0 ? (
                        <div className="flex-1 flex items-center justify-center text-xs text-[var(--foreground-muted)]">
                            {hoveredSeverity ? `No ${hoveredSeverity} MITRE techniques` : 'No MITRE data available'}
                        </div>
                    ) : (
                        <div className="flex-1 flex flex-col justify-center gap-3 overflow-hidden">
                            {filteredMitreData.map((entry, i) => (
                                <MitreBar
                                    key={entry.technique}
                                    entry={entry}
                                    hoveredSeverity={hoveredSeverity}
                                    labelColor={labelColor(entry)}
                                    index={i}
                                />
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </motion.div>
    )
}

'use client';

import { motion } from 'framer-motion';
import { RadialBarChart, RadialBar, ResponsiveContainer } from 'recharts';
import {
    AlertTriangle, XCircle, CheckCircle, RefreshCw, Clock, Link2, Shield, Eye,
} from 'lucide-react';
import { CATEGORY_LABELS, CATEGORY_COLORS, type IncidentDetail } from '@/lib/api-client';

const severityConfig: Record<string, { color: string; bg: string; border: string; text: string; icon: React.ElementType; fill: string }> = {
    critical: { color: 'from-red-500 to-red-600', bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: XCircle, fill: '#ef4444' },
    high: { color: 'from-orange-500 to-orange-600', bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', icon: AlertTriangle, fill: '#f97316' },
    medium: { color: 'from-yellow-500 to-yellow-600', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: AlertTriangle, fill: '#eab308' },
    low: { color: 'from-amber-500 to-amber-600', bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', icon: AlertTriangle, fill: '#f59e0b' },
};

const statusConfig: Record<string, { label: string; color: string; bg: string }> = {
    open: { label: 'Open', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
    investigating: { label: 'Investigating', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30' },
    resolved: { label: 'Resolved', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30' },
    dismissed: { label: 'Dismissed', color: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/30' },
    auto_resolved: { label: 'Auto-resolved', color: 'text-gray-500', bg: 'bg-gray-500/10 border-gray-500/30' },
};

interface IncidentHeaderProps {
    incident: IncidentDetail;
    onRefresh: () => void;
    onStatusUpdate: (status: string) => void;
    onConfirmAction: (action: { status: string; title: string; description: string; variant: 'success' | 'danger' }) => void;
}

function formatDuration(startedAt: string, endedAt: string): string {
    const ms = new Date(endedAt).getTime() - new Date(startedAt).getTime();
    if (ms < 0) return '—';
    const secs = Math.floor(ms / 1000);
    if (secs < 60) return `${secs}s`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m`;
    const hrs = Math.floor(mins / 60);
    const remMins = mins % 60;
    if (hrs < 24) return `${hrs}h ${remMins}m`;
    const days = Math.floor(hrs / 24);
    return `${days}d ${hrs % 24}h`;
}

const cardVariants = {
    hidden: { opacity: 0, y: 12 },
    visible: (i: number) => ({
        opacity: 1, y: 0,
        transition: { delay: 0.2 + i * 0.08, duration: 0.4 },
    }),
};

export { severityConfig, statusConfig };

export default function IncidentHeader({ incident, onRefresh, onStatusUpdate, onConfirmAction }: IncidentHeaderProps) {
    const sevConfig = severityConfig[incident.severity] || severityConfig.medium;
    const SevIcon = sevConfig.icon;
    const stConfig = statusConfig[incident.status] || statusConfig.open;
    const mitre = [...new Set(incident.mitre_techniques || [])];
    const findingCount = incident.finding_ids?.length || 0;
    const confidence = Math.round(incident.confidence * 100);
    const gaugeData = [{ value: confidence, fill: sevConfig.fill }];
    const duration = formatDuration(incident.started_at, incident.ended_at);

    // Severity breakdown of findings
    const findingSeverityCounts = (incident.findings || []).reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm overflow-hidden"
            style={{ borderTopColor: sevConfig.fill, borderTopWidth: 3 }}
        >
            <div className="p-6">
                <div className="flex flex-col lg:flex-row gap-6">

                    {/* Left — Confidence Gauge */}
                    <div className="flex flex-col items-center gap-2 shrink-0">
                        <motion.div
                            initial={{ scale: 0, rotate: -180 }}
                            animate={{ scale: 1, rotate: 0 }}
                            transition={{ type: 'spring', stiffness: 100, damping: 20, duration: 1.2 }}
                            className="relative w-32 h-32"
                        >
                            <ResponsiveContainer width="100%" height="100%">
                                <RadialBarChart
                                    cx="50%" cy="50%"
                                    innerRadius="60%" outerRadius="90%"
                                    barSize={8}
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
                            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                                <span className="text-lg font-bold leading-none" style={{ color: sevConfig.fill }}>
                                    {confidence}%
                                </span>
                                <span className="text-[7px] text-gray-500 uppercase tracking-wider mt-0.5">Confidence</span>
                            </div>
                        </motion.div>
                        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg ${sevConfig.bg} border ${sevConfig.border}`}>
                            <SevIcon className={`w-3.5 h-3.5 ${sevConfig.text}`} />
                            <span className={`text-xs font-semibold uppercase ${sevConfig.text}`}>{incident.severity}</span>
                        </div>
                    </div>

                    {/* Center — Title + Stats */}
                    <div className="flex-1 min-w-0">
                        {/* Title row with refresh */}
                        <div className="flex items-start justify-between gap-3 mb-1">
                            <div className="flex flex-wrap items-center gap-2 min-w-0">
                                <h1 className="text-2xl font-bold text-white truncate">{incident.title}</h1>
                                <span className={`px-2 py-0.5 rounded text-xs border ${stConfig.bg} ${stConfig.color}`}>
                                    {stConfig.label}
                                </span>
                                {incident.category && incident.category !== 'other' && (() => {
                                    const catColors = CATEGORY_COLORS[incident.category] || CATEGORY_COLORS.other;
                                    return (
                                        <span className={`px-2 py-0.5 rounded text-xs border ${catColors.bg} ${catColors.text} ${catColors.border}`}>
                                            {CATEGORY_LABELS[incident.category] || incident.category}
                                        </span>
                                    );
                                })()}
                                {incident.chain_finding_id && (
                                    <span className="flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-orange-500/10 border border-orange-500/20 text-orange-400">
                                        <Link2 className="w-3 h-3" />
                                        Attack Chain
                                    </span>
                                )}
                            </div>
                            <button
                                onClick={onRefresh}
                                className="p-1.5 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-all shrink-0"
                                title="Refresh"
                            >
                                <RefreshCw className="w-3.5 h-3.5 text-gray-500" />
                            </button>
                        </div>

                        {incident.summary && (
                            <p className="text-sm text-gray-400 mb-3 break-words">{incident.summary}</p>
                        )}

                        {/* Mini-stat grid */}
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                            {[
                                {
                                    label: 'Findings', value: findingCount,
                                    extra: (
                                        <div className="h-1 bg-white/5 rounded-full overflow-hidden flex mt-1">
                                            {['critical', 'high', 'medium', 'low'].map(sev => {
                                                const c = findingSeverityCounts[sev] || 0;
                                                if (!c || !findingCount) return null;
                                                return <div key={sev} className="h-full" style={{ width: `${(c / findingCount) * 100}%`, background: (severityConfig[sev] || severityConfig.medium).fill }} />;
                                            })}
                                        </div>
                                    ),
                                },
                                { label: 'Duration', value: duration },
                                {
                                    label: 'Host',
                                    value: incident.host_id?.slice(0, 12) || '—',
                                    mono: true,
                                },
                                { label: 'MITRE', value: `${mitre.length} technique${mitre.length !== 1 ? 's' : ''}` },
                            ].map((stat, i) => (
                                <motion.div
                                    key={stat.label}
                                    custom={i}
                                    variants={cardVariants}
                                    initial="hidden"
                                    animate="visible"
                                    className="rounded-xl bg-white/[0.03] border border-white/[0.06] px-3 py-2"
                                >
                                    <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">{stat.label}</p>
                                    <p className={`text-sm font-semibold text-white ${stat.mono ? 'font-mono' : ''}`}>{stat.value}</p>
                                    {stat.extra}
                                </motion.div>
                            ))}
                        </div>

                        {/* MITRE techniques */}
                        {mitre.length > 0 && (
                            <div className="flex flex-wrap gap-1.5">
                                {mitre.map(t => (
                                    <span key={t} className="px-2 py-0.5 bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[10px] font-mono rounded">
                                        {t}
                                    </span>
                                ))}
                            </div>
                        )}

                        {/* Timestamps */}
                        <div className="flex items-center gap-1.5 mt-2 text-xs text-gray-500">
                            <Clock className="w-3 h-3" />
                            <span>{new Date(incident.started_at).toLocaleString()} — {new Date(incident.ended_at).toLocaleString()}</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* Action Buttons — right-aligned bottom strip */}
            {(incident.status === 'open' || incident.status === 'investigating' || incident.status === 'auto_resolved') && (
                <div className="flex items-center justify-end gap-3 px-6 py-3.5 bg-gradient-to-r from-transparent via-white/[0.01] to-white/[0.03] border-t border-white/5">
                    {(incident.status === 'open' || incident.status === 'auto_resolved') && (
                        <button
                            onClick={() => onStatusUpdate('investigating')}
                            className="px-5 py-2 bg-blue-500/10 border border-blue-500/25 text-blue-400 rounded-xl text-sm font-semibold hover:bg-blue-500/20 hover:border-blue-500/40 hover:shadow-lg hover:shadow-blue-500/5 transition-all duration-200 flex items-center gap-2"
                        >
                            <Eye className="w-4 h-4" />
                            Investigate
                        </button>
                    )}
                    {(incident.status === 'open' || incident.status === 'investigating') && (
                        <>
                            <button
                                onClick={() => onConfirmAction({
                                    status: 'resolved',
                                    title: 'Resolve Incident',
                                    description: `This will resolve this incident and auto-resolve all ${findingCount} constituent finding(s).`,
                                    variant: 'success',
                                })}
                                className="px-5 py-2 bg-green-500/10 border border-green-500/25 text-green-400 rounded-xl text-sm font-semibold hover:bg-green-500/20 hover:border-green-500/40 hover:shadow-lg hover:shadow-green-500/5 transition-all duration-200 flex items-center gap-2"
                            >
                                <CheckCircle className="w-4 h-4" />
                                Resolve
                            </button>
                            <button
                                onClick={() => onConfirmAction({
                                    status: 'dismissed',
                                    title: 'Dismiss Incident',
                                    description: `This will dismiss this incident and dismiss all ${findingCount} constituent finding(s).`,
                                    variant: 'danger',
                                })}
                                className="px-5 py-2 bg-white/[0.04] border border-white/10 text-gray-400 rounded-xl text-sm font-semibold hover:bg-white/[0.08] hover:border-white/20 hover:text-gray-300 transition-all duration-200 flex items-center gap-2"
                            >
                                <XCircle className="w-4 h-4" />
                                Dismiss
                            </button>
                        </>
                    )}
                </div>
            )}
        </motion.div>
    );
}

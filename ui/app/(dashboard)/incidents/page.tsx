'use client';

import { useState, useEffect, useMemo } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
    AlertTriangle, CheckCircle, XCircle, Shield, RefreshCw,
    Clock, Eye, Link2, Search, X, Loader2, Zap, Bot,
} from 'lucide-react';
import { PageHeading } from '@/components/ui/page-heading';
import {
    getIncidents,
    updateIncidentStatus,
    aiAgentDisplayName,
    CATEGORY_LABELS,
    CATEGORY_COLORS,
    type Incident,
    type IncidentCounts,
} from '@/lib/api-client';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import AnimatedNumber from '@/components/dashboard/AnimatedNumber';

const severityConfig: Record<string, { color: string; hex: string; bg: string; border: string; text: string; icon: React.ElementType }> = {
    critical: { color: 'from-red-500 to-red-600', hex: '#ef4444', bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: XCircle },
    high: { color: 'from-orange-500 to-orange-600', hex: '#f97316', bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', icon: AlertTriangle },
    medium: { color: 'from-yellow-500 to-yellow-600', hex: '#eab308', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: AlertTriangle },
    low: { color: 'from-amber-500 to-amber-600', hex: '#f59e0b', bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', icon: AlertTriangle },
};

const statusConfig: Record<string, { label: string; color: string; bg: string }> = {
    open: { label: 'Open', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30' },
    investigating: { label: 'Investigating', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30' },
    resolved: { label: 'Resolved', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30' },
    dismissed: { label: 'Dismissed', color: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/30' },
    auto_resolved: { label: 'Auto-resolved', color: 'text-gray-500', bg: 'bg-gray-500/10 border-gray-500/30' },
};

const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: (i: number) => ({
        opacity: 1, y: 0,
        transition: { delay: 0.15 + i * 0.08, duration: 0.5 },
    }),
};

function GlassCard({ children, className = '', glow }: { children: React.ReactNode; className?: string; glow?: string }) {
    return (
        <div className={`relative bg-[#0d1117]/80 border-2 border-white/[0.07] rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 hover:border-white/[0.13] transition-all duration-300 ${className}`}>
            {glow && <div className="absolute inset-0 rounded-3xl opacity-[0.03] pointer-events-none" style={{ background: `radial-gradient(ellipse at top, ${glow}, transparent 70%)` }} />}
            <div className="relative">{children}</div>
        </div>
    );
}

function formatTimeRange(startedAt: string, endedAt: string): string {
    const start = new Date(startedAt);
    const end = new Date(endedAt);
    const durationMs = end.getTime() - start.getTime();

    if (durationMs < 60000) return '< 1 min';
    if (durationMs < 3600000) return `${Math.round(durationMs / 60000)} min`;
    if (durationMs < 86400000) return `${Math.round(durationMs / 3600000)}h`;
    return `${Math.round(durationMs / 86400000)}d`;
}

function formatRelativeTime(ts: string): string {
    const date = new Date(ts);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

/** Confidence bar color */
function confidenceColor(c: number): string {
    if (c >= 0.85) return '#ef4444';
    if (c >= 0.7) return '#f97316';
    if (c >= 0.5) return '#eab308';
    return '#64748b';
}

type SubTab = 'open' | 'investigating' | 'resolved';

export default function IncidentsPage() {
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [counts, setCounts] = useState<IncidentCounts | null>(null);
    const [loading, setLoading] = useState(true);
    const [subTab, setSubTab] = useState<SubTab>('open');
    const [agentFilter, setAgentFilter] = useState<string>('');
    const [categoryFilter, setCategoryFilter] = useState<string>('');
    const [searchQuery, setSearchQuery] = useState('');
    const [confirmAction, setConfirmAction] = useState<{
        id: string;
        status: string;
        title: string;
        description: string;
        variant: 'danger' | 'success';
    } | null>(null);

    useEffect(() => {
        fetchData();
    }, []);

    async function fetchData() {
        try {
            setLoading(true);
            // Fetch open + investigating separately to ensure they aren't
            // buried by a large volume of auto_resolved in the general query
            const [openResp, investigatingResp, allResp] = await Promise.all([
                getIncidents({ status: 'open', limit: 100 }),
                getIncidents({ status: 'investigating', limit: 100 }),
                getIncidents({ limit: 200 }),
            ]);
            const activeIncidents = [
                ...(openResp.incidents || []),
                ...(investigatingResp.incidents || []),
            ];
            const activeIds = new Set(activeIncidents.map(i => i.id));
            const merged = [
                ...activeIncidents,
                ...(allResp.incidents || []).filter(i => !activeIds.has(i.id)),
            ];
            setIncidents(merged);
            setCounts(allResp.counts);
        } catch (err) {
            console.error('Failed to fetch incidents:', err);
        } finally {
            setLoading(false);
        }
    }

    async function handleStatusUpdate(id: string, status: string) {
        try {
            await updateIncidentStatus(id, status);
            setIncidents(incidents.map(inc =>
                inc.id === id ? { ...inc, status } : inc
            ));
        } catch (err) {
            console.error('Failed to update incident status:', err);
        }
    }

    // Extract all unique agent types across all incidents
    const allAgentTypes = useMemo(() => {
        const agents = new Set<string>();
        for (const inc of incidents) {
            const types = (inc.context_summary?.ai_types as string[]) || [];
            types.forEach(t => agents.add(t));
        }
        return Array.from(agents).sort();
    }, [incidents]);

    // Extract all unique categories across all incidents
    const allCategories = useMemo(() => {
        const cats = new Set<string>();
        for (const inc of incidents) {
            if (inc.category && inc.category !== 'other') cats.add(inc.category);
        }
        return Array.from(cats).sort();
    }, [incidents]);

    // Apply agent filter first, then category filter
    const agentFiltered = agentFilter
        ? incidents.filter(i => {
            const types = (i.context_summary?.ai_types as string[]) || [];
            return types.includes(agentFilter);
        })
        : incidents;

    const categoryFiltered = categoryFilter
        ? agentFiltered.filter(i => i.category === categoryFilter)
        : agentFiltered;

    // Split incidents by tab
    const openIncidents = categoryFiltered.filter(i => i.status === 'open');
    const investigatingIncidents = categoryFiltered.filter(i => i.status === 'investigating');
    const resolvedIncidents = categoryFiltered.filter(i => i.status === 'resolved' || i.status === 'dismissed' || i.status === 'auto_resolved');

    const tabIncidents = subTab === 'open' ? openIncidents
        : subTab === 'investigating' ? investigatingIncidents
        : resolvedIncidents;

    // Apply search filter
    const filteredIncidents = searchQuery.trim()
        ? tabIncidents.filter(i => {
            const q = searchQuery.toLowerCase();
            return (
                i.title.toLowerCase().includes(q) ||
                (i.summary?.toLowerCase().includes(q)) ||
                (i.mitre_techniques?.some(t => t.toLowerCase().includes(q))) ||
                i.severity.toLowerCase().includes(q) ||
                (i.host_id?.toLowerCase().includes(q))
            );
        })
        : tabIncidents;

    // Severity breakdown for stat cards
    const severityBreakdown = useMemo(() => {
        const active = incidents.filter(i => i.status === 'open' || i.status === 'investigating');
        return {
            critical: active.filter(i => i.severity === 'critical').length,
            high: active.filter(i => i.severity === 'high').length,
            medium: active.filter(i => i.severity === 'medium').length,
            low: active.filter(i => i.severity === 'low').length,
        };
    }, [incidents]);

    const totalActive = (counts?.open ?? 0) + (counts?.investigating ?? 0);
    const totalResolved = (counts?.resolved ?? 0) + (counts?.dismissed ?? 0) + (counts?.auto_resolved ?? 0);

    return (
        <div className="space-y-7">
            {/* Header */}
            <PageHeading
                title="Incidents"
                subtitle="Correlated security events grouped for investigation"
                actions={
                    <button
                        onClick={fetchData}
                        className="p-2 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-400 hover:text-white hover:bg-white/[0.06] hover:border-white/[0.13] transition-all duration-200"
                        title="Refresh"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                }
            >
                {totalActive > 0 && (
                    <span className="flex items-center gap-1.5 text-sm bg-red-500/10 text-red-400 px-2.5 py-1 rounded-full border border-red-500/20">
                        <Zap className="w-3 h-3" />
                        {totalActive} active{severityBreakdown.critical > 0 ? ` (${severityBreakdown.critical} critical)` : ''}
                    </span>
                )}
            </PageHeading>

            {/* Rich Stat Cards */}
            {counts && (
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                    {/* Active Incidents card */}
                    <motion.div
                        custom={0} variants={cardVariants} initial="hidden" animate="visible"
                        whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                        className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                        style={{ background: 'linear-gradient(to bottom, #ef44440c, #ef444404)', borderColor: '#ef444430' }}
                    >
                        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #ef44440c, transparent 70%)' }} />
                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #ef444430, transparent 90%)' }} />
                        <div className="relative flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="p-1.5 rounded-xl" style={{ background: '#ef444415' }}>
                                    <AlertTriangle className="w-4 h-4 text-red-400" />
                                </div>
                                <span className="text-xs font-semibold text-red-400 opacity-70">Active</span>
                            </div>
                            <AnimatedNumber value={totalActive} className="text-2xl font-extrabold text-red-400" />
                        </div>
                        <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                            {totalActive > 0 && (
                                <>
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(counts.open / totalActive) * 100}%` }}
                                        transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#ef4444' }}
                                    />
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(counts.investigating / totalActive) * 100}%` }}
                                        transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#3b82f6' }}
                                    />
                                </>
                            )}
                        </div>
                        <div className="relative flex gap-x-3">
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-red-400" />
                                <span className="text-xs text-gray-400">Open</span>
                                <span className="text-sm font-semibold text-white">{counts.open}</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-blue-400" />
                                <span className="text-xs text-gray-400">Investigating</span>
                                <span className="text-sm font-semibold text-white">{counts.investigating}</span>
                            </div>
                        </div>
                    </motion.div>

                    {/* Severity Breakdown card */}
                    <motion.div
                        custom={1} variants={cardVariants} initial="hidden" animate="visible"
                        whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                        className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                        style={{ background: 'linear-gradient(to bottom, #f973160c, #f9731604)', borderColor: '#f9731630' }}
                    >
                        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #f973160c, transparent 70%)' }} />
                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #f9731630, transparent 90%)' }} />
                        <div className="relative flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="p-1.5 rounded-xl" style={{ background: '#f9731615' }}>
                                    <Shield className="w-4 h-4 text-orange-400" />
                                </div>
                                <span className="text-xs font-semibold text-orange-400 opacity-70">By Severity</span>
                            </div>
                            <span className="text-2xl font-extrabold text-white">{totalActive}</span>
                        </div>
                        <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                            {totalActive > 0 && (['critical', 'high', 'medium', 'low'] as const).map((sev, i) => {
                                const count = severityBreakdown[sev];
                                if (count === 0) return null;
                                return (
                                    <motion.div
                                        key={sev}
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(count / totalActive) * 100}%` }}
                                        transition={{ delay: 0.5 + i * 0.1, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full"
                                        style={{ background: severityConfig[sev].hex }}
                                    />
                                );
                            })}
                        </div>
                        <div className="relative flex flex-wrap gap-x-3 gap-y-1">
                            {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
                                <div key={sev} className="flex items-center gap-1.5">
                                    <span className="w-2 h-2 rounded-full" style={{ background: severityConfig[sev].hex }} />
                                    <span className="text-xs text-gray-400 capitalize">{sev}</span>
                                    <span className="text-sm font-semibold text-white">{severityBreakdown[sev]}</span>
                                </div>
                            ))}
                        </div>
                    </motion.div>

                    {/* Resolved card */}
                    <motion.div
                        custom={2} variants={cardVariants} initial="hidden" animate="visible"
                        whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                        className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                        style={{ background: 'linear-gradient(to bottom, #22c55e0c, #22c55e04)', borderColor: '#22c55e30' }}
                    >
                        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #22c55e0c, transparent 70%)' }} />
                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #22c55e30, transparent 90%)' }} />
                        <div className="relative flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="p-1.5 rounded-xl" style={{ background: '#22c55e15' }}>
                                    <CheckCircle className="w-4 h-4 text-green-400" />
                                </div>
                                <span className="text-xs font-semibold text-green-400 opacity-70">Resolved</span>
                            </div>
                            <AnimatedNumber value={totalResolved} className="text-2xl font-extrabold text-green-400" />
                        </div>
                        <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                            {totalResolved > 0 && (
                                <>
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(counts.resolved / totalResolved) * 100}%` }}
                                        transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#22c55e' }}
                                    />
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(counts.dismissed / totalResolved) * 100}%` }}
                                        transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#64748b' }}
                                    />
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(counts.auto_resolved / totalResolved) * 100}%` }}
                                        transition={{ delay: 0.7, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#818cf8' }}
                                    />
                                </>
                            )}
                        </div>
                        <div className="relative flex flex-wrap gap-x-3 gap-y-1">
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-green-400" />
                                <span className="text-xs text-gray-400">Resolved</span>
                                <span className="text-sm font-semibold text-white">{counts.resolved}</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-gray-400" />
                                <span className="text-xs text-gray-400">Dismissed</span>
                                <span className="text-sm font-semibold text-white">{counts.dismissed}</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full bg-indigo-400" />
                                <span className="text-xs text-gray-400">Auto</span>
                                <span className="text-sm font-semibold text-white">{counts.auto_resolved}</span>
                            </div>
                        </div>
                    </motion.div>

                    {/* Total / Resolution Rate card */}
                    <motion.div
                        custom={3} variants={cardVariants} initial="hidden" animate="visible"
                        whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                        className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                        style={{ background: 'linear-gradient(to bottom, #a855f70c, #a855f704)', borderColor: '#a855f730' }}
                    >
                        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #a855f70c, transparent 70%)' }} />
                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #a855f730, transparent 90%)' }} />
                        <div className="relative flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <div className="p-1.5 rounded-xl" style={{ background: '#a855f715' }}>
                                    <Clock className="w-4 h-4 text-purple-400" />
                                </div>
                                <span className="text-xs font-semibold text-purple-400 opacity-70">Total</span>
                            </div>
                            <AnimatedNumber value={counts.total} className="text-2xl font-extrabold text-white" />
                        </div>
                        <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                            {counts.total > 0 && (
                                <>
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(totalActive / counts.total) * 100}%` }}
                                        transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#ef4444' }}
                                    />
                                    <motion.div
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(totalResolved / counts.total) * 100}%` }}
                                        transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                        className="h-full" style={{ background: '#22c55e' }}
                                    />
                                </>
                            )}
                        </div>
                        <div className="relative text-xs text-gray-400">
                            {counts.total > 0
                                ? `${Math.round((totalResolved / counts.total) * 100)}% resolution rate`
                                : 'No incidents yet'}
                        </div>
                    </motion.div>
                </div>
            )}

            {/* Tabs + Search row */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                    <button
                        onClick={() => setSubTab('open')}
                        className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${subTab === 'open'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                        Open
                        <span className="text-xs tabular-nums opacity-60">{openIncidents.length}</span>
                    </button>
                    <button
                        onClick={() => setSubTab('investigating')}
                        className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${subTab === 'investigating'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
                        Investigating
                        <span className="text-xs tabular-nums opacity-60">{investigatingIncidents.length}</span>
                    </button>
                    <button
                        onClick={() => setSubTab('resolved')}
                        className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${subTab === 'resolved'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                        Resolved
                        <span className="text-xs tabular-nums opacity-60">{resolvedIncidents.length}</span>
                    </button>
                </div>

                {/* Agent filter */}
                {allAgentTypes.length > 1 && (
                    <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                        <button
                            onClick={() => setAgentFilter('')}
                            className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${!agentFilter
                                ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                            }`}
                        >
                            All Agents
                        </button>
                        {allAgentTypes.map(agent => {
                            const count = incidents.filter(i =>
                                ((i.context_summary?.ai_types as string[]) || []).includes(agent)
                            ).length;
                            return (
                                <button
                                    key={agent}
                                    onClick={() => setAgentFilter(agentFilter === agent ? '' : agent)}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${agentFilter === agent
                                        ? 'bg-cyan-500/15 text-cyan-400 shadow-sm border border-cyan-500/25'
                                        : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                    }`}
                                >
                                    <Bot className="w-3 h-3" />
                                    {aiAgentDisplayName(agent)}
                                    <span className="text-xs tabular-nums opacity-60">{count}</span>
                                </button>
                            );
                        })}
                    </div>
                )}

                {/* Category filter */}
                {allCategories.length > 1 && (
                    <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1 flex-wrap gap-0.5">
                        <button
                            onClick={() => setCategoryFilter('')}
                            className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 ${!categoryFilter
                                ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                            }`}
                        >
                            All Categories
                        </button>
                        {allCategories.map(cat => {
                            const catColors = CATEGORY_COLORS[cat] || CATEGORY_COLORS.other;
                            const count = agentFiltered.filter(i => i.category === cat).length;
                            return (
                                <button
                                    key={cat}
                                    onClick={() => setCategoryFilter(categoryFilter === cat ? '' : cat)}
                                    className={`px-3 py-1.5 text-sm font-medium rounded-xl transition-all duration-200 flex items-center gap-1.5 ${categoryFilter === cat
                                        ? `${catColors.bg} ${catColors.text} shadow-sm border ${catColors.border}`
                                        : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                    }`}
                                >
                                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: catColors.hex }} />
                                    {CATEGORY_LABELS[cat] || cat}
                                    <span className="text-xs tabular-nums opacity-60">{count}</span>
                                </button>
                            );
                        })}
                    </div>
                )}

                {/* Search */}
                <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                    <input
                        type="text"
                        placeholder="Search incidents..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8 pr-8 py-2 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-orange-500/40 focus:ring-1 focus:ring-orange-500/20 w-56"
                    />
                    {searchQuery && (
                        <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
                            <X className="w-3.5 h-3.5" />
                        </button>
                    )}
                </div>

                {searchQuery && (
                    <span className="text-sm text-gray-500 tabular-nums">{filteredIncidents.length} results</span>
                )}
            </div>

            {/* Incidents List */}
            <AnimatePresence mode="wait">
                {loading ? (
                    <motion.div
                        key="loading"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="flex items-center justify-center py-16 text-gray-400 gap-3"
                    >
                        <Loader2 className="w-5 h-5 animate-spin" />
                        <span>Loading incidents...</span>
                    </motion.div>
                ) : filteredIncidents.length === 0 ? (
                    <motion.div
                        key="empty"
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.3 }}
                    >
                        <GlassCard className="p-12 text-center">
                            <motion.div
                                initial={{ scale: 0 }}
                                animate={{ scale: 1 }}
                                transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
                            >
                                <Shield className="w-14 h-14 text-green-400/50 mx-auto mb-4" />
                            </motion.div>
                            <h3 className="text-xl font-semibold mb-2">
                                {searchQuery
                                    ? 'No Matching Incidents'
                                    : subTab === 'open' ? 'No Open Incidents'
                                    : subTab === 'investigating' ? 'No Incidents Under Investigation'
                                    : 'No Resolved Incidents'}
                            </h3>
                            <p className="text-gray-400 max-w-md mx-auto">
                                {searchQuery
                                    ? 'Try a different search term'
                                    : subTab === 'open' ? 'All incidents have been triaged'
                                    : subTab === 'investigating' ? 'No incidents are currently being investigated'
                                    : 'No incidents have been resolved yet'}
                            </p>
                            {searchQuery && (
                                <button
                                    onClick={() => setSearchQuery('')}
                                    className="mt-4 px-4 py-2 text-sm bg-white/5 border border-white/10 rounded-lg text-gray-300 hover:bg-white/10 transition-all"
                                >
                                    Clear search
                                </button>
                            )}
                        </GlassCard>
                    </motion.div>
                ) : (
                    <motion.div
                        key={`list-${subTab}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="space-y-3"
                    >
                        {filteredIncidents.map((inc, idx) => {
                            const sevConfig = severityConfig[inc.severity] || severityConfig.medium;
                            const SevIcon = sevConfig.icon;
                            const stConfig = statusConfig[inc.status] || statusConfig.open;
                            const findingCount = inc.finding_ids?.length || 0;
                            const mitre = inc.mitre_techniques || [];
                            const contextSummary = inc.context_summary || {};
                            const aiTypes = (contextSummary.ai_types as string[]) || [];
                            const confPct = Math.round(inc.confidence * 100);
                            const hex = sevConfig.hex;

                            return (
                                <motion.div
                                    key={inc.id}
                                    initial={{ opacity: 0, y: 15 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ delay: Math.min(idx * 0.04, 0.3), duration: 0.3 }}
                                    whileHover={{ y: -2 }}
                                    className="group"
                                >
                                    <div
                                        className="relative rounded-2xl border overflow-hidden transition-all duration-300 hover:shadow-lg"
                                        style={{
                                            background: `linear-gradient(135deg, ${hex}08, transparent 60%)`,
                                            borderColor: `${hex}20`,
                                            // @ts-expect-error CSS custom prop
                                            '--hover-shadow': `0 8px 30px ${hex}15`,
                                        }}
                                        onMouseEnter={(e) => { (e.currentTarget.style.boxShadow = `0 8px 30px ${hex}15`); (e.currentTarget.style.borderColor = `${hex}40`); }}
                                        onMouseLeave={(e) => { (e.currentTarget.style.boxShadow = 'none'); (e.currentTarget.style.borderColor = `${hex}20`); }}
                                    >
                                        {/* Subtle top glow line */}
                                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 5%, ${hex}40, transparent 95%)` }} />

                                        <div className="relative p-4">
                                            {/* Row 1: severity dot + title + badges + time */}
                                            <div className="flex items-center gap-3">
                                                <div className="p-1.5 rounded-lg shrink-0" style={{ background: `${hex}15` }}>
                                                    <SevIcon className="w-4 h-4" style={{ color: hex }} />
                                                </div>

                                                <Link
                                                    href={`/incidents/${encodeURIComponent(inc.id)}`}
                                                    className="text-[15px] font-semibold text-white/90 hover:text-white transition-colors truncate"
                                                >
                                                    {inc.title}
                                                </Link>

                                                <div className="flex items-center gap-1.5 shrink-0 ml-auto">
                                                    <span
                                                        className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
                                                        style={{ color: hex, background: `${hex}15` }}
                                                    >
                                                        {inc.severity}
                                                    </span>
                                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${stConfig.bg} ${stConfig.color}`}>
                                                        {stConfig.label}
                                                    </span>
                                                    {inc.category && inc.category !== 'other' && (() => {
                                                        const catColors = CATEGORY_COLORS[inc.category] || CATEGORY_COLORS.other;
                                                        return (
                                                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${catColors.bg} ${catColors.text} border ${catColors.border}`}>
                                                                {CATEGORY_LABELS[inc.category] || inc.category}
                                                            </span>
                                                        );
                                                    })()}
                                                    {inc.chain_finding_id && (
                                                        <span className="flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-500/10 text-orange-400">
                                                            <Link2 className="w-2.5 h-2.5" />
                                                            Chain
                                                        </span>
                                                    )}
                                                    {aiTypes.length > 0 && (
                                                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-cyan-500/10 text-cyan-300">
                                                            <Bot className="w-2.5 h-2.5" />
                                                            {aiTypes.join(', ')}
                                                        </span>
                                                    )}
                                                    <span className="text-xs text-gray-500 tabular-nums ml-1 flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {formatRelativeTime(inc.created_at)}
                                                    </span>
                                                </div>
                                            </div>

                                            {/* Row 2: summary (compact) */}
                                            {inc.summary && (
                                                <p className="text-xs text-gray-500 font-mono mt-2 ml-10 truncate">
                                                    {inc.summary}
                                                </p>
                                            )}

                                            {/* Row 3: inline stats + mitre */}
                                            <div className="flex items-center gap-3 mt-2.5 ml-10 flex-wrap">
                                                <span className="flex items-center gap-1 text-xs text-gray-400">
                                                    <AlertTriangle className="w-3 h-3 text-orange-400/60" />
                                                    <span className="font-semibold text-white/80">{findingCount}</span> finding{findingCount !== 1 ? 's' : ''}
                                                </span>
                                                <span className="text-white/10">|</span>
                                                <span className="flex items-center gap-1 text-xs text-gray-400">
                                                    <Clock className="w-3 h-3 text-blue-400/60" />
                                                    <span className="font-semibold text-white/80">{formatTimeRange(inc.started_at, inc.ended_at)}</span>
                                                </span>
                                                <span className="text-white/10">|</span>
                                                <span className="flex items-center gap-1 text-xs">
                                                    <div className="w-8 h-1 bg-white/10 rounded-full overflow-hidden">
                                                        <div className="h-full rounded-full" style={{ width: `${confPct}%`, background: confidenceColor(inc.confidence) }} />
                                                    </div>
                                                    <span className="font-semibold tabular-nums" style={{ color: confidenceColor(inc.confidence) }}>{confPct}%</span>
                                                </span>
                                                {inc.host_id && (
                                                    <>
                                                        <span className="text-white/10">|</span>
                                                        <span className="text-xs font-mono text-gray-500">{inc.host_id.slice(0, 12)}</span>
                                                    </>
                                                )}

                                                {mitre.length > 0 && (
                                                    <>
                                                        <span className="text-white/10">|</span>
                                                        {mitre.slice(0, 4).map((t) => (
                                                            <span
                                                                key={t}
                                                                className="px-1.5 py-0.5 bg-purple-500/8 text-purple-400/80 text-[10px] font-mono rounded"
                                                            >
                                                                {t}
                                                            </span>
                                                        ))}
                                                        {mitre.length > 4 && (
                                                            <span className="text-[10px] text-gray-500">+{mitre.length - 4}</span>
                                                        )}
                                                    </>
                                                )}
                                            </div>
                                        </div>

                                        {/* Actions — slide up on hover */}
                                        <div className="flex items-center justify-end gap-2 px-4 py-2.5 border-t transition-all duration-200 opacity-0 max-h-0 group-hover:opacity-100 group-hover:max-h-16 overflow-hidden" style={{ borderColor: `${hex}10` }}>
                                            <Link
                                                href={`/incidents/${encodeURIComponent(inc.id)}`}
                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 hover:scale-105"
                                                style={{ color: hex, background: `${hex}10` }}
                                            >
                                                <Eye className="w-3.5 h-3.5" />
                                                Details
                                            </Link>
                                            {(inc.status === 'open' || inc.status === 'auto_resolved') && (
                                                <button
                                                    onClick={() => handleStatusUpdate(inc.id, 'investigating')}
                                                    className="px-3 py-1.5 bg-blue-500/10 text-blue-400 rounded-lg text-xs font-semibold hover:bg-blue-500/20 hover:scale-105 transition-all duration-200 flex items-center gap-1.5"
                                                >
                                                    <Search className="w-3.5 h-3.5" />
                                                    Investigate
                                                </button>
                                            )}
                                            {(inc.status === 'open' || inc.status === 'investigating') && (
                                                <>
                                                    <button
                                                        onClick={() => setConfirmAction({
                                                            id: inc.id,
                                                            status: 'resolved',
                                                            title: 'Resolve Incident',
                                                            description: `This will resolve incident "${inc.title}" and auto-resolve all ${findingCount} constituent finding(s).`,
                                                            variant: 'success',
                                                        })}
                                                        className="px-3 py-1.5 bg-green-500/10 text-green-400 rounded-lg text-xs font-semibold hover:bg-green-500/20 hover:scale-105 transition-all duration-200 flex items-center gap-1.5"
                                                    >
                                                        <CheckCircle className="w-3.5 h-3.5" />
                                                        Resolve
                                                    </button>
                                                    <button
                                                        onClick={() => setConfirmAction({
                                                            id: inc.id,
                                                            status: 'dismissed',
                                                            title: 'Dismiss Incident',
                                                            description: `This will dismiss incident "${inc.title}" and dismiss all ${findingCount} constituent finding(s).`,
                                                            variant: 'danger',
                                                        })}
                                                        className="px-3 py-1.5 bg-white/[0.04] text-gray-400 rounded-lg text-xs font-semibold hover:bg-white/[0.08] hover:text-gray-300 hover:scale-105 transition-all duration-200 flex items-center gap-1.5"
                                                    >
                                                        <XCircle className="w-3.5 h-3.5" />
                                                        Dismiss
                                                    </button>
                                                </>
                                            )}
                                        </div>
                                    </div>
                                </motion.div>
                            );
                        })}
                    </motion.div>
                )}
            </AnimatePresence>

            <ConfirmDialog
                open={confirmAction !== null}
                onConfirm={() => {
                    if (confirmAction) {
                        handleStatusUpdate(confirmAction.id, confirmAction.status);
                    }
                    setConfirmAction(null);
                }}
                onCancel={() => setConfirmAction(null)}
                title={confirmAction?.title || ''}
                description={confirmAction?.description || ''}
                confirmLabel={confirmAction?.status === 'resolved' ? 'Resolve' : 'Dismiss'}
                confirmVariant={confirmAction?.variant || 'danger'}
            />
        </div>
    );
}

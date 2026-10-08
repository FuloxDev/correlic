'use client';

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Clock, Shield, Link2, Filter, ChevronDown, Cpu, FileText, Globe, Wifi } from 'lucide-react';
import type { TimelineEntry } from '@/lib/api-client';
import ExpandableText from './ExpandableText';

const SEVERITY_COLORS: Record<string, string> = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#f59e0b',
};

const TYPE_CONFIG: Record<string, { icon: React.ElementType; dot: string; ring: string; line: string; label: string }> = {
    chain:   { icon: Link2,  dot: 'bg-orange-500', ring: 'ring-orange-500/30', line: 'bg-orange-500/20', label: 'Chain' },
    finding: { icon: Shield, dot: 'bg-purple-500', ring: 'ring-purple-500/30', line: 'bg-purple-500/20', label: 'Finding' },
    event:   { icon: Cpu,    dot: 'bg-gray-500',   ring: 'ring-gray-500/20',   line: 'bg-white/5',       label: 'Event' },
};

const EVENT_TYPE_ICONS: Record<string, React.ElementType> = {
    process_exec: Cpu,
    process_exit: Cpu,
    file_open: FileText,
    net_connect: Globe,
    net_dns: Wifi,
};

interface IncidentTimelineProps {
    timeline: TimelineEntry[];
    startedAt: string;
    endedAt: string;
}

export default function IncidentTimeline({ timeline, startedAt, endedAt }: IncidentTimelineProps) {
    const [typeFilter, setTypeFilter] = useState<string | null>(null);
    const [sevFilter, setSevFilter] = useState<string | null>(null);
    const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
    const [showAll, setShowAll] = useState(false);

    const filtered = useMemo(() => {
        let result = timeline;
        if (typeFilter) result = result.filter(e => e.type === typeFilter);
        if (sevFilter) result = result.filter(e => e.severity === sevFilter);
        return result;
    }, [timeline, typeFilter, sevFilter]);

    const displayEntries = showAll ? filtered : filtered.slice(0, 50);
    const hasMore = filtered.length > 50 && !showAll;

    const typeCounts = useMemo(() => {
        const counts: Record<string, number> = {};
        for (const e of timeline) counts[e.type] = (counts[e.type] || 0) + 1;
        return counts;
    }, [timeline]);

    return (
        <div className="bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold flex items-center gap-2">
                    <Clock className="w-5 h-5 text-orange-400" />
                    Timeline
                    <span className="text-xs text-dim font-normal ml-1">
                        ({filtered.length}{filtered.length !== timeline.length ? ` of ${timeline.length}` : ''} events)
                    </span>
                </h2>
            </div>

            {/* Filter bar */}
            <div className="flex flex-wrap items-center gap-2 mb-4">
                <Filter className="w-3.5 h-3.5 text-dim" />
                {/* Type filters */}
                {Object.entries(TYPE_CONFIG).map(([key, cfg]) => {
                    const count = typeCounts[key] || 0;
                    if (!count) return null;
                    const active = typeFilter === key;
                    return (
                        <button
                            key={key}
                            onClick={() => setTypeFilter(active ? null : key)}
                            className={`px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all border ${
                                active
                                    ? `${cfg.dot.replace('bg-', 'bg-')}/20 border-current ${cfg.dot.replace('bg-', 'text-').replace('-500', '-400')}`
                                    : 'bg-white/5 border-white/10 text-gray-400 hover:text-white hover:bg-white/10'
                            }`}
                        >
                            {cfg.label} ({count})
                        </button>
                    );
                })}
                <span className="w-px h-4 bg-white/10" />
                {/* Severity filters */}
                {['critical', 'high', 'medium', 'low'].map(sev => {
                    const count = timeline.filter(e => e.severity === sev).length;
                    if (!count) return null;
                    const active = sevFilter === sev;
                    return (
                        <button
                            key={sev}
                            onClick={() => setSevFilter(active ? null : sev)}
                            className={`px-2 py-1 rounded-lg text-[11px] transition-all border ${
                                active
                                    ? 'border-current'
                                    : 'bg-white/5 border-white/10 text-gray-400 hover:text-white hover:bg-white/10'
                            }`}
                            style={active ? { color: SEVERITY_COLORS[sev], borderColor: SEVERITY_COLORS[sev], backgroundColor: `${SEVERITY_COLORS[sev]}15` } : undefined}
                        >
                            {sev}
                        </button>
                    );
                })}
                {(typeFilter || sevFilter) && (
                    <button
                        onClick={() => { setTypeFilter(null); setSevFilter(null); }}
                        className="text-[10px] text-dim hover:text-white transition-colors underline"
                    >
                        Clear
                    </button>
                )}
            </div>

            {/* Timeline entries */}
            <div className={`relative space-y-0 ${showAll ? '' : 'max-h-[600px] overflow-y-auto'}`}>
                {displayEntries.map((entry, idx) => {
                    const cfg = TYPE_CONFIG[entry.type] || TYPE_CONFIG.event;
                    const Icon = entry.event_type ? (EVENT_TYPE_ICONS[entry.event_type] || cfg.icon) : cfg.icon;
                    const isExpanded = expandedIdx === idx;
                    const sevColor = entry.severity ? SEVERITY_COLORS[entry.severity] : undefined;
                    const nextEntry = displayEntries[idx + 1];
                    const nextCfg = nextEntry ? (TYPE_CONFIG[nextEntry.type] || TYPE_CONFIG.event) : null;

                    return (
                        <div key={`${entry.timestamp}-${idx}`} className="relative flex gap-3">
                            {/* Vertical line + dot */}
                            <div className="flex flex-col items-center shrink-0" style={{ width: 22 }}>
                                <motion.div
                                    initial={{ scale: 0 }}
                                    animate={{ scale: 1 }}
                                    transition={{ delay: Math.min(idx * 0.02, 0.5) }}
                                    className={`w-[22px] h-[22px] rounded-full ring-2 ${cfg.ring} ${cfg.dot} flex items-center justify-center z-10`}
                                    style={sevColor ? { boxShadow: `0 0 8px ${sevColor}40` } : undefined}
                                >
                                    <Icon className="w-3 h-3 text-white" />
                                </motion.div>
                                {idx < displayEntries.length - 1 && (
                                    <div
                                        className="w-0.5 flex-1 min-h-[20px]"
                                        style={{
                                            background: sevColor && nextEntry?.severity
                                                ? `linear-gradient(to bottom, ${sevColor}40, ${SEVERITY_COLORS[nextEntry.severity] || '#ffffff10'}40)`
                                                : nextCfg ? undefined : undefined,
                                        }}
                                    >
                                        <div className={`w-full h-full ${!sevColor ? cfg.line : ''}`} />
                                    </div>
                                )}
                            </div>

                            {/* Content */}
                            <div
                                className={`flex-1 pb-4 cursor-pointer group transition-colors rounded-lg -mx-1 px-1 ${isExpanded ? 'bg-white/[0.02]' : 'hover:bg-white/[0.02]'}`}
                                onClick={() => setExpandedIdx(isExpanded ? null : idx)}
                            >
                                <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-sm text-gray-200 font-medium break-words flex-1 min-w-0">
                                        {entry.title || entry.event_type || 'Event'}
                                    </span>
                                    {entry.severity && (
                                        <span
                                            className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase border"
                                            style={{ color: SEVERITY_COLORS[entry.severity], borderColor: `${SEVERITY_COLORS[entry.severity]}40`, backgroundColor: `${SEVERITY_COLORS[entry.severity]}10` }}
                                        >
                                            {entry.severity}
                                        </span>
                                    )}
                                    <span className={`text-[9px] px-1.5 py-0.5 rounded ${cfg.dot}/20 text-white/60`}>
                                        {entry.type}
                                    </span>
                                    <span className="text-[10px] text-dim tabular-nums shrink-0">
                                        {new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                    </span>
                                    {entry.pid && <span className="text-[10px] text-dim font-mono">PID {entry.pid}</span>}
                                    <ChevronDown className={`w-3 h-3 text-dim transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                </div>

                                <AnimatePresence>
                                    {isExpanded && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: 'auto', opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            transition={{ duration: 0.2 }}
                                            className="overflow-hidden"
                                        >
                                            <div className="pt-2 space-y-1.5">
                                                {entry.detail && (
                                                    <ExpandableText text={entry.detail} mono maxLines={4} className="text-gray-400" />
                                                )}
                                                {entry.event_type && (
                                                    <div className="text-[10px] text-dim">
                                                        Event type: <span className="text-gray-300 font-mono">{entry.event_type}</span>
                                                    </div>
                                                )}
                                                {entry.finding_id && (
                                                    <div className="text-[10px] text-purple-400 font-mono break-all">
                                                        Finding: {entry.finding_id}
                                                    </div>
                                                )}
                                                {entry.properties && Object.keys(entry.properties).length > 0 && (
                                                    <div className="text-[10px] space-y-0.5 mt-1">
                                                        {Object.entries(entry.properties).map(([k, v]) => (
                                                            <div key={k} className="flex gap-2">
                                                                <span className="text-dim shrink-0">{k}:</span>
                                                                <span className="text-gray-300 font-mono break-all">{String(v)}</span>
                                                            </div>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Show all / show less */}
            {hasMore && (
                <button
                    onClick={() => setShowAll(true)}
                    className="mt-3 w-full py-2 text-xs text-gray-400 hover:text-white bg-white/[0.02] hover:bg-white/5 rounded-lg transition-all border border-white/5"
                >
                    Show all {filtered.length} events
                </button>
            )}
            {showAll && filtered.length > 50 && (
                <button
                    onClick={() => setShowAll(false)}
                    className="mt-3 w-full py-2 text-xs text-gray-400 hover:text-white bg-white/[0.02] hover:bg-white/5 rounded-lg transition-all border border-white/5"
                >
                    Collapse
                </button>
            )}
        </div>
    );
}

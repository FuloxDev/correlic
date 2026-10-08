'use client';

import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
    Activity,
    RefreshCw,
    Cpu,
    FileText,
    Terminal,
    Globe,
    Zap,
    Search,
    Wifi,
    Clock,
    ChevronRight,
    Bot
} from 'lucide-react';
import { getAgentActivity, type AgentActivityResponse, type AgentSummary as AgentSummaryType, type AgentAction } from '@/lib/api-client';
import { PageHeading } from '@/components/ui/page-heading';
import AnimatedNumber from '@/components/dashboard/AnimatedNumber';

const intervalOptions = [
    { label: '5m', value: 5 },
    { label: '15m', value: 15 },
    { label: '30m', value: 30 },
    { label: '1h', value: 60 },
    { label: '6h', value: 360 },
    { label: '24h', value: 1440 },
];



function GlassCard({ children, className = '', glow, ...props }: React.HTMLAttributes<HTMLDivElement> & { glow?: string }) {
    return (
        <div className={`relative bg-[#0d1117]/80 border-2 border-white/[0.07] rounded-3xl backdrop-blur-md shadow-lg shadow-black/20 hover:border-white/[0.13] transition-all duration-300 ${className}`} {...props}>
            {glow && <div className="absolute inset-0 rounded-3xl opacity-[0.03] pointer-events-none" style={{ background: `radial-gradient(ellipse at top, ${glow}, transparent 70%)` }} />}
            <div className="relative">{children}</div>
        </div>
    );
}

function formatDuration(ms: number): string {
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const remainingMins = minutes % 60;
    return remainingMins > 0 ? `${hours}h ${remainingMins}m` : `${hours}h`;
}

function formatTime(timestamp: string): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}





// --- Activity Stream Components ---

const significanceColors: Record<number, { bg: string; border: string; text: string; dot: string; hex: string }> = {
    5: { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-300', dot: 'bg-red-400', hex: '#ef4444' },
    4: { bg: 'bg-orange-500/10', border: 'border-orange-500/20', text: 'text-orange-300', dot: 'bg-orange-400', hex: '#f97316' },
    3: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-300', dot: 'bg-yellow-400', hex: '#eab308' },
    2: { bg: 'bg-blue-500/10', border: 'border-blue-500/20', text: 'text-blue-300', dot: 'bg-blue-400', hex: '#3b82f6' },
    1: { bg: 'bg-gray-500/10', border: 'border-gray-500/20', text: 'text-gray-400', dot: 'bg-gray-500', hex: '#64748b' },
};

const categoryIcons: Record<string, { icon: typeof FileText; color: string }> = {
    file: { icon: FileText, color: 'text-blue-400' },
    network: { icon: Globe, color: 'text-cyan-400' },
    command: { icon: Terminal, color: 'text-green-400' },
    dns: { icon: Search, color: 'text-purple-400' },
};

function ActionRow({ action, agentComm }: { action: AgentAction; agentComm: string }) {
    const colors = significanceColors[action.significance] || significanceColors[2];
    const cat = categoryIcons[action.category] || { icon: Activity, color: 'text-gray-400' };
    const Icon = cat.icon;
    const time = new Date(action.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const processComm = action.process_comm || '';
    const isChild = processComm && processComm !== agentComm;
    const isHighSig = action.significance >= 4;
    const hasDetail = action.detail && action.detail !== action.action;

    return (
        <div
            className="group/action relative rounded-xl border transition-all duration-300"
            style={{ background: `linear-gradient(135deg, ${colors.hex}06, transparent 60%)`, borderColor: `${colors.hex}15` }}
            onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 4px 20px ${colors.hex}10`; e.currentTarget.style.borderColor = `${colors.hex}30`; }}
            onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = `${colors.hex}15`; }}
        >
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 10%, ${colors.hex}25, transparent 90%)` }} />
            <div className="relative flex items-center gap-3 px-4 py-2.5">
                {/* Significance dot */}
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: colors.hex }} />

                {/* Category icon */}
                <div className={`p-1.5 rounded-lg shrink-0 ${cat.color}`} style={{ background: `${colors.hex}10` }}>
                    <Icon className="w-3.5 h-3.5" />
                </div>

                {/* Action text */}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                        <span className="text-sm text-gray-200">{action.action}</span>
                        {/* S1-S3: detail on hover only */}
                        {hasDetail && !isHighSig && (
                            <span className="text-xs text-dim truncate hidden group-hover/action:inline" title={action.detail}>
                                {action.detail!.length > 60 ? action.detail!.slice(0, 57) + '...' : action.detail}
                            </span>
                        )}
                    </div>
                    {/* S4+: detail always visible inline */}
                    {hasDetail && isHighSig && (
                        <p className="text-[11px] text-dim font-mono truncate mt-0.5" title={action.detail}>
                            {action.detail!.length > 100 ? action.detail!.slice(0, 97) + '...' : action.detail}
                        </p>
                    )}
                    {isChild && (
                        <span className="text-[10px] text-dim font-mono">
                            via {processComm}{action.process_pid ? ` (${action.process_pid})` : ''}
                        </span>
                    )}
                </div>

                {/* Significance badge */}
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider shrink-0" style={{ color: colors.hex, background: `${colors.hex}15` }}>
                    S{action.significance}
                </span>

                {/* Timestamp */}
                <span className="text-xs text-dim w-20 text-right font-mono tabular-nums shrink-0">
                    {time}
                </span>
            </div>
        </div>
    );
}

// --- Action Grouping ---

interface ActionGroup {
    actions: AgentAction[];
    category: string;
    count: number;
    firstTime: string;
    lastTime: string;
    representative: AgentAction; // first action in the group, used for display
}

function groupActions(actions: AgentAction[]): ActionGroup[] {
    if (!actions || actions.length === 0) return [];

    const groups: ActionGroup[] = [];
    let currentGroup: ActionGroup | null = null;

    for (const action of actions) {
        const ts = new Date(action.timestamp).getTime();

        if (
            currentGroup &&
            currentGroup.category === action.category &&
            action.significance < 4 && // never group high-sig actions
            currentGroup.representative.significance < 4 &&
            ts - new Date(currentGroup.lastTime).getTime() <= 2000
        ) {
            currentGroup.actions.push(action);
            currentGroup.count++;
            currentGroup.lastTime = action.timestamp;
        } else {
            if (currentGroup) groups.push(currentGroup);
            currentGroup = {
                actions: [action],
                category: action.category,
                count: 1,
                firstTime: action.timestamp,
                lastTime: action.timestamp,
                representative: action,
            };
        }
    }
    if (currentGroup) groups.push(currentGroup);

    return groups;
}

const categoryLabels: Record<string, string> = {
    file: 'File operations',
    network: 'Network connections',
    command: 'Commands',
    dns: 'DNS lookups',
};

function GroupedActionRow({ group, agentComm }: { group: ActionGroup; agentComm: string }) {
    const [expanded, setExpanded] = useState(false);

    // Single action — render normally
    if (group.count === 1) {
        return <ActionRow action={group.representative} agentComm={agentComm} />;
    }

    const colors = significanceColors[group.representative.significance] || significanceColors[2];
    const cat = categoryIcons[group.category] || { icon: Activity, color: 'text-gray-400' };
    const Icon = cat.icon;
    const label = categoryLabels[group.category] || group.category;
    const timeRange = `${formatTime(group.firstTime)} – ${formatTime(group.lastTime)}`;

    return (
        <div>
            <div
                className="relative rounded-xl border cursor-pointer transition-all duration-300"
                style={{ background: `linear-gradient(135deg, ${colors.hex}06, transparent 60%)`, borderColor: `${colors.hex}15` }}
                onClick={() => setExpanded(!expanded)}
                onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 4px 20px ${colors.hex}10`; e.currentTarget.style.borderColor = `${colors.hex}30`; }}
                onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = `${colors.hex}15`; }}
            >
                <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 10%, ${colors.hex}25, transparent 90%)` }} />
                <div className="relative flex items-center gap-3 px-4 py-2.5">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: colors.hex }} />
                    <div className={`p-1.5 rounded-lg shrink-0 ${cat.color}`} style={{ background: `${colors.hex}10` }}>
                        <Icon className="w-3.5 h-3.5" />
                    </div>
                    <div className="flex-1 min-w-0">
                        <span className="text-sm text-gray-300">
                            {label} <span className="text-dim">(×{group.count})</span>
                        </span>
                    </div>
                    <span className="text-xs text-dim font-mono">{timeRange}</span>
                    <ChevronRight className={`w-3.5 h-3.5 text-dim transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`} />
                </div>
            </div>
            {expanded && (
                <div className="ml-6 mt-1.5 space-y-1 rounded-xl bg-black/30 border border-white/[0.05] p-2">
                    {group.actions.map((action, idx) => (
                        <ActionRow key={`${action.event_id}-${idx}`} action={action} agentComm={agentComm} />
                    ))}
                </div>
            )}
        </div>
    );
}

const PAGE_SIZE = 50;

function AgentCard({ agent, isExpanded, onToggle }: {
    agent: AgentSummaryType;
    isExpanded: boolean;
    onToggle: () => void;
}) {
    const [searchQuery, setSearchQuery] = useState('');
    const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
    const sentinelRef = useRef<HTMLDivElement>(null);
    const totalActions = agent.actions?.length || 0;
    const highSigCount = agent.actions?.filter(a => a.significance >= 4).length || 0;

    // Reset the visible window when the search changes or the card collapses
    // (state adjustment during render instead of an effect).
    const resetKey = `${isExpanded ? 1 : 0}:${searchQuery}`;
    const [prevResetKey, setPrevResetKey] = useState(resetKey);
    if (prevResetKey !== resetKey) {
        setPrevResetKey(resetKey);
        setVisibleCount(PAGE_SIZE);
    }

    // Filter actions by search query
    const filteredActions = searchQuery.trim()
        ? (agent.actions || []).filter(a => {
            const q = searchQuery.toLowerCase();
            return (a.action?.toLowerCase().includes(q)) || (a.detail?.toLowerCase().includes(q));
        })
        : (agent.actions || []);

    // Group filtered actions — only the visible slice
    const visibleActions = filteredActions.slice(0, visibleCount);
    const groups = groupActions(visibleActions);
    const hasMore = visibleCount < filteredActions.length;

    // Infinite scroll: observe sentinel element
    useEffect(() => {
        if (!isExpanded || !hasMore) return;
        const sentinel = sentinelRef.current;
        if (!sentinel) return;

        const observer = new IntersectionObserver(
            (entries) => {
                if (entries[0].isIntersecting) {
                    setVisibleCount(prev => prev + PAGE_SIZE);
                }
            },
            { rootMargin: '200px' }
        );
        observer.observe(sentinel);
        return () => observer.disconnect();
    }, [isExpanded, hasMore, visibleCount]);

    return (
        <div className="space-y-3">
            {/* Agent header */}
            <div
                className="group/agent relative rounded-2xl border overflow-hidden transition-all duration-300 cursor-pointer"
                style={{
                    background: totalActions > 0
                        ? 'linear-gradient(135deg, #06b6d408, transparent 60%)'
                        : 'linear-gradient(135deg, #64748b06, transparent 60%)',
                    borderColor: totalActions > 0 ? '#06b6d420' : '#64748b15',
                }}
                onClick={onToggle}
                onMouseEnter={(e) => { e.currentTarget.style.boxShadow = '0 8px 30px #06b6d415'; e.currentTarget.style.borderColor = '#06b6d440'; }}
                onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = totalActions > 0 ? '#06b6d420' : '#64748b15'; }}
            >
                <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 5%, #06b6d440, transparent 95%)' }} />
                <div className="relative flex items-center justify-between p-4">
                    <div className="flex items-center gap-3">
                        <div className="p-1.5 rounded-lg" style={{ background: '#06b6d415' }}>
                            <Bot className="w-5 h-5 text-cyan-400" />
                        </div>
                        <span className="text-[15px] font-semibold text-white/90 truncate">{agent.agent_name}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-cyan-500/15 text-cyan-300 rounded-full font-medium border border-cyan-500/20">
                            {agent.ai_type}
                        </span>
                        <span className="text-xs text-dim tabular-nums">{totalActions} action{totalActions !== 1 ? 's' : ''}</span>
                    </div>
                    <div className="flex items-center gap-2">
                        {agent.stats.files_modified > 0 && (
                            <span className="flex items-center gap-1 text-xs px-2 py-1 bg-blue-500/10 text-blue-300 rounded-full border border-blue-500/20">
                                <FileText className="w-3 h-3" />
                                {agent.stats.files_modified}
                            </span>
                        )}
                        {agent.stats.commands_run > 0 && (
                            <span className="flex items-center gap-1 text-xs px-2 py-1 bg-green-500/10 text-green-300 rounded-full border border-green-500/20">
                                <Terminal className="w-3 h-3" />
                                {agent.stats.commands_run}
                            </span>
                        )}
                        {agent.stats.connections > 0 && (
                            <span className="flex items-center gap-1 text-xs px-2 py-1 bg-indigo-500/10 text-indigo-300 rounded-full border border-indigo-500/20">
                                <Globe className="w-3 h-3" />
                                {agent.stats.connections}
                            </span>
                        )}
                        {highSigCount > 0 && (
                            <span className="flex items-center gap-1 text-xs px-2 py-1 bg-red-500/10 text-red-300 rounded-full border border-red-500/20">
                                <Zap className="w-3 h-3" />
                                {highSigCount}
                            </span>
                        )}
                        <ChevronRight className={`w-4 h-4 text-dim transition-transform duration-200 ${isExpanded ? 'rotate-90' : ''}`} />
                    </div>
                </div>
                {/* Inline stats */}
                <div className="flex items-center gap-3 px-4 pb-3 flex-wrap">
                    <span className="text-xs text-dim">PID: <span className="text-gray-400 font-mono">{agent.agent_pid}</span></span>
                    <span className="text-white/10">|</span>
                    <span className="text-xs text-dim">{agent.duration}</span>
                    <span className="text-white/10">|</span>
                    <span className="text-xs text-dim">{agent.child_count} subprocess{agent.child_count !== 1 ? 'es' : ''}</span>
                </div>
            </div>

            {/* Actions list — dark inset panel */}
            {isExpanded && (
                <div className="ml-4 md:ml-5 pl-4 md:pl-6 border-l border-white/[0.06]">
                    {totalActions === 0 ? (
                        <div className="py-6 text-center text-dim text-sm italic">
                            No significant actions in this time window
                        </div>
                    ) : (
                        <div className="rounded-2xl bg-black/30 border border-white/[0.05] px-4 py-3 space-y-1.5 max-h-[50vh] overflow-y-auto">
                            {/* Search input */}
                            <div className="flex items-center gap-2 mb-2">
                                <div className="relative flex-1">
                                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-dim" />
                                    <input
                                        type="text"
                                        placeholder="Search actions..."
                                        value={searchQuery}
                                        onChange={(e) => setSearchQuery(e.target.value)}
                                        onClick={(e) => e.stopPropagation()}
                                        className="w-full pl-8 pr-3 py-1.5 text-xs bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-xl text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/20"
                                    />
                                </div>
                                {searchQuery && (
                                    <span className="text-[11px] text-dim whitespace-nowrap">
                                        {filteredActions.length} of {totalActions} actions
                                    </span>
                                )}
                            </div>

                            {filteredActions.length === 0 ? (
                                <div className="py-4 text-center text-dim text-sm">
                                    No actions match &quot;{searchQuery}&quot;
                                </div>
                            ) : (
                                <>
                                    {groups.map((group, idx) => (
                                        <GroupedActionRow key={`group-${idx}`} group={group} agentComm={agent.agent_name} />
                                    ))}
                                    {hasMore && (
                                        <div ref={sentinelRef} className="flex items-center justify-center py-3 text-xs text-dim">
                                            Showing {visibleCount} of {filteredActions.length} actions — scroll for more
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

function ActivityStreamView({
    data,
    loading,
    error
}: {
    data: AgentActivityResponse | null;
    loading: boolean;
    error: string | null;
}) {
    const [expandedAgents, setExpandedAgents] = useState<Set<number>>(new Set());

    // Auto-expand the first agent the first time data arrives.
    const [seenData, setSeenData] = useState<AgentActivityResponse | null>(null);
    if (data !== seenData) {
        setSeenData(data);
        if (data?.agents?.length && expandedAgents.size === 0) {
            setExpandedAgents(new Set([data.agents[0].agent_pid]));
        }
    }

    const toggleAgent = (pid: number) => {
        setExpandedAgents(prev => {
            const next = new Set(prev);
            if (next.has(pid)) next.delete(pid);
            else next.add(pid);
            return next;
        });
    };

    if (loading && !data) {
        return (
            <GlassCard className="p-12">
                <div className="flex items-center justify-center text-gray-400">
                    <RefreshCw className="w-6 h-6 animate-spin mr-3" />
                    Loading agent activity...
                </div>
            </GlassCard>
        );
    }

    if (error) {
        return (
            <GlassCard className="p-12">
                <div className="text-center text-red-400">{error}</div>
            </GlassCard>
        );
    }

    if (!data?.agents?.length) {
        return (
            <GlassCard className="p-12">
                <div className="text-center text-gray-400">
                    <Cpu className="w-12 h-12 mx-auto mb-3 opacity-30" />
                    <p className="text-lg font-medium mb-1">No AI agents detected</p>
                    <p className="text-sm">No AI agent processes were found in this time window.</p>
                </div>
            </GlassCard>
        );
    }

    // Aggregate stats
    const totalActions = data.agents.reduce((sum, a) => sum + (a.actions?.length || 0), 0);
    const totalFiles = data.agents.reduce((sum, a) => sum + a.stats.files_modified, 0);
    const totalFilesRead = data.agents.reduce((sum, a) => sum + a.stats.files_read, 0);
    const totalCommands = data.agents.reduce((sum, a) => sum + a.stats.commands_run, 0);
    const totalConns = data.agents.reduce((sum, a) => sum + a.stats.connections, 0);
    const totalDNS = data.agents.reduce((sum, a) => sum + a.stats.dns_lookups, 0);
    const totalEvents = data.agents.reduce((sum, a) => sum + a.stats.total_events, 0);
    const totalSubprocesses = data.agents.reduce((sum, a) => sum + a.child_count, 0);
    const highSigTotal = data.agents.reduce((sum, a) => sum + (a.actions?.filter(act => act.significance >= 4).length || 0), 0);

    // Per-agent type breakdown
    const agentTypeMap: Record<string, number> = {};
    for (const a of data.agents) {
        const t = a.ai_type || 'unknown';
        agentTypeMap[t] = (agentTypeMap[t] || 0) + 1;
    }
    const agentTypes = Object.entries(agentTypeMap).sort((a, b) => b[1] - a[1]);

    const AGENT_COLORS: Record<string, string> = {
        claude: '#f59e0b', cursor: '#3b82f6', copilot: '#10b981',
        aider: '#ec4899', codeium: '#8b5cf6', continue: '#ef4444',
    };
    const FALLBACK_COLORS = ['#06b6d4', '#f97316', '#84cc16', '#e879f9'];

    const cardVariants = {
        hidden: { opacity: 0, y: 20 },
        visible: (i: number) => ({
            opacity: 1, y: 0,
            transition: { delay: 0.2 + i * 0.1, duration: 0.5 },
        }),
    };

    const statCards: { label: string; icon: typeof Activity; hex: string; color: string; value: number; barContent: React.ReactNode; legend: React.ReactNode }[] = [
        {
            label: 'Activity', icon: Activity, hex: '#f97316', color: 'text-orange-400', value: totalActions,
            barContent: (() => {
                const total = totalFiles + totalFilesRead + totalCommands + totalConns + totalDNS;
                if (total === 0) return null;
                return [
                    { v: totalFiles, c: '#3b82f6' }, { v: totalFilesRead, c: '#22d3ee' },
                    { v: totalCommands, c: '#22c55e' }, { v: totalConns, c: '#818cf8' }, { v: totalDNS, c: '#a78bfa' },
                ].map((s, i) => {
                    const pct = (s.v / total) * 100;
                    return pct > 0 ? <motion.div key={i} initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={{ delay: 0.6 + i * 0.1, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: s.c }} /> : null;
                });
            })(),
            legend: (
                <>
                    <div className="flex items-center gap-1.5"><FileText className="w-3 h-3 text-blue-400" /><span className="text-[10px] text-gray-400">Edited</span><span className="text-xs font-semibold text-white">{totalFiles.toLocaleString()}</span></div>
                    <div className="flex items-center gap-1.5"><FileText className="w-3 h-3 text-cyan-400" /><span className="text-[10px] text-gray-400">Read</span><span className="text-xs font-semibold text-white">{totalFilesRead.toLocaleString()}</span></div>
                    <div className="flex items-center gap-1.5"><Zap className="w-3 h-3 text-orange-400" /><span className="text-[10px] text-gray-400">Events</span><span className="text-xs font-semibold text-white">{totalEvents.toLocaleString()}</span></div>
                </>
            ),
        },
        {
            label: 'Commands', icon: Terminal, hex: '#22c55e', color: 'text-green-400', value: totalCommands,
            barContent: (() => {
                const total = highSigTotal + Math.max(0, totalCommands - highSigTotal);
                if (total === 0) return null;
                return (
                    <>
                        <motion.div initial={{ width: 0 }} animate={{ width: `${(highSigTotal / total) * 100}%` }} transition={{ delay: 0.7, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: '#f43f5e' }} />
                        <motion.div initial={{ width: 0 }} animate={{ width: `${((total - highSigTotal) / total) * 100}%` }} transition={{ delay: 0.8, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: '#22c55e' }} />
                    </>
                );
            })(),
            legend: (
                <>
                    <div className="flex items-center gap-1.5"><Zap className="w-3 h-3 text-red-400" /><span className="text-[10px] text-gray-400">High-sig</span><span className="text-xs font-semibold text-white">{highSigTotal.toLocaleString()}</span></div>
                    <div className="flex items-center gap-1.5"><Cpu className="w-3 h-3 text-cyan-400" /><span className="text-[10px] text-gray-400">Subprocesses</span><span className="text-xs font-semibold text-white">{totalSubprocesses.toLocaleString()}</span></div>
                </>
            ),
        },
        {
            label: 'Network', icon: Wifi, hex: '#818cf8', color: 'text-indigo-400', value: totalConns + totalDNS,
            barContent: (() => {
                const total = totalConns + totalDNS;
                if (total === 0) return null;
                return (
                    <>
                        <motion.div initial={{ width: 0 }} animate={{ width: `${(totalConns / total) * 100}%` }} transition={{ delay: 0.7, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: '#818cf8' }} />
                        <motion.div initial={{ width: 0 }} animate={{ width: `${(totalDNS / total) * 100}%` }} transition={{ delay: 0.8, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: '#a78bfa' }} />
                    </>
                );
            })(),
            legend: (
                <>
                    <div className="flex items-center gap-1.5"><Globe className="w-3 h-3 text-indigo-400" /><span className="text-[10px] text-gray-400">Connections</span><span className="text-xs font-semibold text-white">{totalConns.toLocaleString()}</span></div>
                    <div className="flex items-center gap-1.5"><Search className="w-3 h-3 text-purple-400" /><span className="text-[10px] text-gray-400">DNS</span><span className="text-xs font-semibold text-white">{totalDNS.toLocaleString()}</span></div>
                </>
            ),
        },
        {
            label: 'AI Agents', icon: Cpu, hex: '#06b6d4', color: 'text-cyan-400', value: data.agents.length,
            barContent: (() => {
                const total = data.agents.length;
                if (total === 0) return null;
                return agentTypes.map(([type, count], i) => {
                    const color = AGENT_COLORS[type.toLowerCase()] || FALLBACK_COLORS[i % FALLBACK_COLORS.length];
                    return <motion.div key={type} initial={{ width: 0 }} animate={{ width: `${(count / total) * 100}%` }} transition={{ delay: 0.6 + i * 0.1, duration: 0.8, ease: 'easeOut' }} className="h-full" style={{ background: color }} />;
                });
            })(),
            legend: agentTypes.map(([type, count], i) => {
                const color = AGENT_COLORS[type.toLowerCase()] || FALLBACK_COLORS[i % FALLBACK_COLORS.length];
                return <div key={type} className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ background: color }} /><span className="text-[10px] text-gray-400 capitalize">{type}</span><span className="text-xs font-semibold text-white">{count}</span></div>;
            }),
        },
    ];

    return (
        <div className="space-y-4">
            {/* Rich stat cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
                {statCards.map((card, idx) => {
                    const CardIcon = card.icon;
                    return (
                        <motion.div
                            key={card.label}
                            custom={idx} variants={cardVariants} initial="hidden" animate="visible"
                            whileHover={{ scale: 1.03, y: -2 }}
                            whileTap={{ scale: 0.98 }}
                            className="group/tile relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                            style={{
                                background: `linear-gradient(to bottom, ${card.hex}0c, ${card.hex}04)`,
                                borderColor: `${card.hex}30`,
                            }}
                        >
                            {/* Radial glow */}
                            <div className="absolute inset-0 pointer-events-none transition-opacity duration-300" style={{ background: `radial-gradient(circle at 50% 0%, ${card.hex}0c, transparent 70%)` }} />
                            {/* Top edge highlight */}
                            <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 10%, ${card.hex}30, transparent 90%)` }} />
                            <div className="relative flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                    <div className="p-1.5 rounded-xl transition-all duration-300" style={{ background: `${card.hex}15` }}>
                                        <CardIcon className={`w-4 h-4 ${card.color}`} />
                                    </div>
                                    <span className={`text-xs font-semibold ${card.color} opacity-70`}>{card.label}</span>
                                </div>
                                <AnimatedNumber value={card.value} className="text-2xl font-extrabold text-white" />
                            </div>
                            <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                                {card.barContent}
                            </div>
                            <div className="relative flex flex-wrap gap-x-3 gap-y-1">
                                {card.legend}
                            </div>
                        </motion.div>
                    );
                })}
            </div>

            {/* Agent cards */}
            {data.agents.map((agent) => (
                <AgentCard
                    key={`${agent.host_id}-${agent.ai_type}-${agent.agent_pid}`}
                    agent={agent}
                    isExpanded={expandedAgents.has(agent.agent_pid)}
                    onToggle={() => toggleAgent(agent.agent_pid)}
                />
            ))}
        </div>
    );
}


export default function Timeline() {
    const [interval, setInterval_] = useState(60);
    const [activityData, setActivityData] = useState<AgentActivityResponse | null>(null);
    const [activityLoading, setActivityLoading] = useState(true);
    const [activityError, setActivityError] = useState<string | null>(null);
    const [minSignificance, setMinSignificance] = useState(2);

    const [reloadNonce, setReloadNonce] = useState(0);

    useEffect(() => {
        let cancelled = false;
        getAgentActivity(interval, minSignificance)
            .then(response => {
                if (cancelled) return;
                setActivityData(response);
                setActivityError(null);
            })
            .catch(err => {
                if (cancelled) return;
                console.error('Failed to fetch agent activity:', err);
                setActivityError('Failed to load agent activity');
            })
            .finally(() => { if (!cancelled) setActivityLoading(false); });
        return () => { cancelled = true; };
    }, [interval, minSignificance, reloadNonce]);

    const changeInterval = (value: number) => { setInterval_(value); setActivityLoading(true); };
    const changeSignificance = (value: number) => { setMinSignificance(value); setActivityLoading(true); };
    const fetchActivityData = () => { setActivityLoading(true); setReloadNonce(n => n + 1); };

    return (
        <div className="space-y-7">
            {/* Header */}
            <PageHeading
                title="Agent Activity"
                subtitle="What your AI agents are doing — files, commands, connections"
                actions={
                    <div className="flex flex-wrap items-center gap-2">
                        {/* Interval Selector */}
                        <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                            {intervalOptions.map((opt) => (
                                <button
                                    key={opt.value}
                                    onClick={() => changeInterval(opt.value)}
                                    className={`px-2.5 py-1.5 text-[11px] font-semibold rounded-xl transition-all duration-200 ${interval === opt.value
                                        ? 'bg-white/[0.12] border border-white/[0.08] text-white shadow-sm'
                                        : 'text-white/30 hover:text-white/60 hover:bg-white/[0.03]'
                                        }`}
                                >
                                    {opt.label}
                                </button>
                            ))}
                        </div>

                        {/* Significance Filter */}
                        <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                            <span className="px-2 text-[10px] text-dim uppercase tracking-wider">Sig</span>
                            {[1, 2, 3, 4, 5].map((sig) => (
                                <button
                                    key={sig}
                                    onClick={() => changeSignificance(sig)}
                                    className={`px-2 py-1.5 text-[11px] font-semibold rounded-xl transition-all duration-200 ${minSignificance === sig
                                        ? 'bg-white/[0.12] border border-white/[0.08] text-white shadow-sm'
                                        : 'text-white/30 hover:text-white/60 hover:bg-white/[0.03]'
                                        }`}
                                    title={`Show significance >= ${sig}`}
                                >
                                    {sig}+
                                </button>
                            ))}
                        </div>

                        {/* Refresh button */}
                        <button
                            onClick={fetchActivityData}
                            disabled={activityLoading}
                            className="p-2 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-400 hover:text-white hover:border-white/[0.13] transition-all disabled:opacity-50"
                            title="Refresh"
                        >
                            <RefreshCw className={`w-4 h-4 ${activityLoading ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                }
            >
                {activityData?.window_start && activityData?.window_end && (
                    <span className="flex items-center gap-1.5 text-xs text-dim bg-[#0d1117]/60 px-2.5 py-1 rounded-full border border-white/[0.07]">
                        <Clock className="w-3 h-3" />
                        {new Date(activityData.window_start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        {' – '}
                        {new Date(activityData.window_end).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                )}
            </PageHeading>

            <ActivityStreamView
                data={activityData}
                loading={activityLoading}
                error={activityError}
            />
        </div>
    );
}

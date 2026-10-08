'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
    AlertTriangle,
    CheckCircle,
    XCircle,
    Shield,
    RefreshCw,
    ChevronDown,
    ArrowLeft,
    Eye,
    Bot,
    Send,
    Sparkles,
    Loader2,
    FileText,
    Globe,
    Terminal,
    Info,
    GitBranch,
    Cpu,
    FolderOpen,
    Brain,
    Lock,
    BarChart2,
    CheckSquare,
    Activity
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import AnimatedNumber from '@/components/dashboard/AnimatedNumber';
import {
    getIncident,
    updateIncidentStatus,
    explainIncident,
    askAboutIncident,
    streamChatAboutIncident,
    getChatHistory,
    deleteChatThread,
    resolveFindingDomain,
    resolveFinding,
    resolveFindingWithExpiry,
    addSafeDomain,
    createBaseline,
    type IncidentDetail,
    type AIExplanation,
    type DomainResolution
} from '@/lib/api-client';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import IncidentHeader, { severityConfig, statusConfig } from '@/components/incidents/IncidentHeader';
import IncidentTimeline from '@/components/incidents/IncidentTimeline';
import ProcessTreeView from '@/components/incidents/ProcessTreeView';
import EventGraphView from '@/components/incidents/EventGraphView';
import ExpandableText from '@/components/incidents/ExpandableText';

function GlassCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
    return (
        <div className={`bg-white/5 border border-orange-900/20 rounded-2xl backdrop-blur-sm ${className}`}>
            {children}
        </div>
    );
}

// ─── Finding Context Details ────────────────────────────────────────
function FindingContext({ context }: { context: Record<string, unknown> }) {
    const [expanded, setExpanded] = useState(false);

    const sensitiveFiles = context.sensitive_files as string[] | undefined;
    const files = Array.isArray(context.files) ? context.files as string[] : undefined;
    const fileCount = context.file_count as number | undefined;
    const filePath = context.file_path as string | undefined;
    const dstIP = context.dst_ip as string | undefined;
    const dstPort = context.dst_port as number | undefined;
    const domain = context.domain as string | undefined;
    const comm = context.comm as string | undefined;
    const aiType = context.ai_type as string | undefined;
    const signalType = context.signal_type as string | undefined;
    const pid = context.pid as number | undefined;

    const hasSensitiveFiles = sensitiveFiles && sensitiveFiles.length > 0;
    const hasFiles = files && files.length > 0;
    const hasNetworkInfo = dstIP || domain;
    const hasFileInfo = filePath && !hasSensitiveFiles;
    if (!hasSensitiveFiles && !hasFiles && !hasNetworkInfo && !hasFileInfo) return null;

    return (
        <div className="mt-1.5 mb-1.5">
            <button
                onClick={() => setExpanded(!expanded)}
                className="flex items-center gap-1.5 text-[11px] text-purple-400/80 hover:text-purple-300 transition-colors"
            >
                <Info className="w-3 h-3" />
                <span>
                    {hasSensitiveFiles ? `${sensitiveFiles.length} sensitive file(s)` : hasFiles ? `${files.length} file(s) modified` : 'Details'}
                    {hasNetworkInfo ? ` + network context` : ''}
                </span>
                <ChevronDown className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`} />
            </button>
            {expanded && (
                <div className="mt-2 p-3 bg-black/30 rounded-md border border-white/5 space-y-2">
                    {hasSensitiveFiles && (
                        <div>
                            <div className="flex items-center gap-1.5 text-[11px] text-gray-400 mb-1">
                                <FileText className="w-3 h-3" />
                                <span>Sensitive files accessed ({sensitiveFiles.length})</span>
                            </div>
                            <div className="space-y-0.5 ml-4">
                                {sensitiveFiles.map((file, i) => (
                                    <div key={i} className="text-[11px] font-mono text-gray-300 break-all" title={file}>
                                        {file}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {hasFiles && (
                        <div>
                            <div className="flex items-center gap-1.5 text-[11px] text-gray-400 mb-1">
                                <FileText className="w-3 h-3" />
                                <span>Files modified ({files.length}{fileCount && fileCount > files.length ? ` of ${fileCount}` : ''})</span>
                            </div>
                            <div className="space-y-0.5 ml-4 max-h-48 overflow-y-auto">
                                {files.map((file, i) => (
                                    <div key={i} className="text-[11px] font-mono text-gray-300 break-all" title={file}>
                                        {file}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {hasFileInfo && (
                        <div className="flex items-center gap-1.5 text-[11px]">
                            <FileText className="w-3 h-3 text-gray-400" />
                            <span className="text-gray-400">File:</span>
                            <span className="font-mono text-gray-300 break-all">{filePath}</span>
                        </div>
                    )}
                    {hasNetworkInfo && (
                        <div className="flex items-center gap-1.5 text-[11px]">
                            <Globe className="w-3 h-3 text-gray-400" />
                            <span className="text-gray-400">Destination:</span>
                            <span className="font-mono text-gray-300">
                                {domain ? `${domain} (${dstIP}:${dstPort})` : `${dstIP}:${dstPort}`}
                            </span>
                        </div>
                    )}
                    {(comm || pid) && (
                        <div className="flex items-center gap-1.5 text-[11px]">
                            <Terminal className="w-3 h-3 text-gray-400" />
                            <span className="text-gray-400">Process:</span>
                            <span className="font-mono text-gray-300">
                                {comm || aiType}{pid ? ` (PID ${pid})` : ''}
                            </span>
                        </div>
                    )}
                    {signalType && (
                        <div className="flex items-center gap-1.5 text-[11px]">
                            <span className="text-gray-400 ml-[18px]">Signal:</span>
                            <span className="px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 text-[10px]">
                                {signalType}
                            </span>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

// ─── AI Analysis Helpers ────────────────────────────────────────────

function parseSections(content: string): { title: string; body: string }[] {
    const lines = content.split('\n');
    const sections: { title: string; body: string[] }[] = [];
    let current: { title: string; body: string[] } | null = null;
    for (const line of lines) {
        const match = line.match(/^#{2,3}\s+(.+)/);
        if (match) {
            if (current) sections.push({ title: current.title, body: current.body });
            current = { title: match[1].trim(), body: [] };
        } else if (current) {
            current.body.push(line);
        }
    }
    if (current) sections.push({ title: current.title, body: current.body });
    if (sections.length === 0) return [{ title: '', body: content }];
    return sections.map(s => ({ title: s.title, body: s.body.join('\n').trim() }));
}

const SECTION_CONFIG: Record<string, { icon: React.ElementType; color: string }> = {
    'What Happened':            { icon: FileText,     color: '#f97316' },
    'Network Destinations':     { icon: Globe,        color: '#3b82f6' },
    'Process Chain':            { icon: Activity,     color: '#a855f7' },
    'Sensitive Files Accessed': { icon: Lock,         color: '#f43f5e' },
    'Why It Matters':           { icon: AlertTriangle,color: '#eab308' },
    'Confidence Assessment':    { icon: BarChart2,    color: '#06b6d4' },
    'Recommended Actions':      { icon: CheckSquare,  color: '#22c55e' },
};

const mdComponents = {
    table: (props: React.HTMLAttributes<HTMLTableElement>) => (
        <div className="overflow-x-auto my-2">
            <table className="text-xs border-collapse w-full" {...props} />
        </div>
    ),
    th: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
        <th className="border border-white/10 px-2 py-1 text-left text-gray-400 bg-white/5" {...props} />
    ),
    td: (props: React.HTMLAttributes<HTMLTableCellElement>) => (
        <td className="border border-white/10 px-2 py-1" {...props} />
    ),
    code: ({ className, children, ...props }: React.HTMLAttributes<HTMLElement> & { className?: string }) => {
        const isInline = !className;
        return isInline
            ? <code className="bg-white/10 px-1.5 py-0.5 rounded text-cyan-300 text-xs" {...props}>{children}</code>
            : <code className={`${className ?? ''} block bg-black/30 p-3 rounded-lg text-xs overflow-x-auto`} {...props}>{children}</code>;
    },
};

function ReasoningPanel({ reasoning }: { reasoning: string }) {
    const [open, setOpen] = useState(false);
    return (
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] overflow-hidden">
            <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/[0.03] transition-colors"
            >
                <div className="flex items-center gap-2.5">
                    <Brain className="w-4 h-4 text-purple-400" />
                    <span className="text-xs font-semibold text-purple-300 uppercase tracking-wider">AI Reasoning Steps</span>
                    <span className="text-[10px] text-dim font-normal normal-case tracking-normal">— how the risk score was derived</span>
                </div>
                <ChevronDown className={`w-4 h-4 text-dim transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
            </button>
            <AnimatePresence initial={false}>
                {open && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.25 }}
                        className="overflow-hidden"
                    >
                        <div className="px-4 pb-4 border-t border-white/[0.05]">
                            <div className="mt-3 prose prose-invert prose-sm max-w-none text-dim text-xs leading-relaxed">
                                <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                                    {reasoning}
                                </ReactMarkdown>
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

// ─── Main Page ──────────────────────────────────────────────────────

export default function IncidentDetailPage() {
    const params = useParams();
    const router = useRouter();
    const incidentId = typeof params.id === 'string' ? decodeURIComponent(params.id) : '';

    const [incident, setIncident] = useState<IncidentDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [findingsOpen, setFindingsOpen] = useState(true);
    const [confirmAction, setConfirmAction] = useState<{
        status: string;
        title: string;
        description: string;
        variant: 'danger' | 'success';
    } | null>(null);
    const [graphTab, setGraphTab] = useState<'tree' | 'graph'>('tree');

    // AI state
    const [aiExplanation, setAiExplanation] = useState<AIExplanation | null>(null);
    const [aiLoading, setAiLoading] = useState(false);
    const [aiError, setAiError] = useState<string | null>(null);
    const [aiOpen, setAiOpen] = useState(true);
    const [deepMode, setDeepMode] = useState(false);
    const [askInput, setAskInput] = useState('');
    const [askHistory, setAskHistory] = useState<{ role: 'user' | 'assistant'; content: string; tokens?: { input: number; output: number }; model?: string }[]>([]);
    const [askLoading, setAskLoading] = useState(false);
    const [toolActivity, setToolActivity] = useState<string | null>(null);
    const [threadId, setThreadId] = useState<string | undefined>(undefined);
    const [domainResolutions, setDomainResolutions] = useState<Record<string, DomainResolution>>({});
    const [domainLoading, setDomainLoading] = useState<Record<string, boolean>>({});
    const [allowDropdownOpen, setAllowDropdownOpen] = useState<string | null>(null);
    const [dirAllowTarget, setDirAllowTarget] = useState<{ path: string; detectionId: string; aiType: string } | null>(null);
    const [allowTarget, setAllowTarget] = useState<{ id: string; baselineMode?: string; label: string } | null>(null);
    const [allowDuration, setAllowDuration] = useState<string>('');

    const fetchedRef = useRef<string | null>(null);

    async function fetchIncident() {
        try {
            setLoading(true);
            setError(null);
            const detail = await getIncident(incidentId);
            setIncident(detail);
        } catch (err) {
            console.error('Failed to fetch incident:', err);
            setError('Failed to load incident details');
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => {
        if (!incidentId || fetchedRef.current === incidentId) return;
        fetchedRef.current = incidentId;
        fetchIncident();
    }, [incidentId]);

    // Restore conversation thread from sessionStorage on mount
    useEffect(() => {
        if (!incidentId) return;
        const storedThreadId = sessionStorage.getItem(`correlic:thread:${incidentId}`);
        if (!storedThreadId) return;
        setThreadId(storedThreadId);
        getChatHistory(incidentId, storedThreadId)
            .then(msgs => {
                if (msgs.length > 0) {
                    setAskHistory(msgs.map(m => ({ role: m.role, content: m.content })));
                }
            })
            .catch(() => {
                // Thread may have expired — clear stale ID
                sessionStorage.removeItem(`correlic:thread:${incidentId}`);
            });
    }, [incidentId]);

    async function handleNewConversation() {
        if (threadId) {
            deleteChatThread(incidentId, threadId).catch(() => {});
        }
        sessionStorage.removeItem(`correlic:thread:${incidentId}`);
        setThreadId(undefined);
        setAskHistory([]);
    }

    async function handleStatusUpdate(status: string) {
        if (!incident) return;
        try {
            await updateIncidentStatus(incidentId, status);
            setIncident({ ...incident, status });
        } catch (err) {
            console.error('Failed to update incident status:', err);
        }
    }

    async function handleExplainIncident() {
        setAiLoading(true);
        setAiError(null);
        try {
            const result = await explainIncident(incidentId, deepMode ? 'deep' : undefined);
            setAiExplanation(result);
        } catch (err: unknown) {
            setAiError(err instanceof Error ? err.message : 'Failed to get AI explanation');
        } finally {
            setAiLoading(false);
        }
    }

    async function handleAskQuestion(directQuestion?: string) {
        const q = directQuestion || askInput.trim();
        if (!q || askLoading) return;
        const question = q;
        setAskInput('');
        setAskHistory(prev => [...prev, { role: 'user', content: question }]);
        setAskLoading(true);

        setAskHistory(prev => [...prev, { role: 'assistant', content: '' }]);

        try {
            await streamChatAboutIncident(
                incidentId,
                question,
                threadId,
                (tid) => {
                    // First event: thread_id — persist so we can restore on reload
                    setThreadId(tid);
                    sessionStorage.setItem(`correlic:thread:${incidentId}`, tid);
                },
                (delta) => {
                    setAskHistory(prev => {
                        const updated = [...prev];
                        const last = updated[updated.length - 1];
                        if (last?.role === 'assistant') {
                            updated[updated.length - 1] = { ...last, content: last.content + delta };
                        }
                        return updated;
                    });
                },
                (stats) => {
                    setAskHistory(prev => {
                        const updated = [...prev];
                        const last = updated[updated.length - 1];
                        if (last?.role === 'assistant') {
                            updated[updated.length - 1] = { ...last, tokens: stats.tokens, model: stats.model };
                        }
                        return updated;
                    });
                },
                (errMsg) => {
                    setAskHistory(prev => {
                        const updated = [...prev];
                        if (updated.length > 0 && updated[updated.length - 1]?.role === 'assistant') {
                            updated[updated.length - 1] = { role: 'assistant', content: `Error: ${errMsg}` };
                        }
                        return updated;
                    });
                },
                (tool) => {
                    setToolActivity(tool.status === 'running' ? tool.name : null);
                },
            );
        } catch {
            // Fallback to legacy non-streaming endpoint
            setAskHistory(prev => {
                const updated = [...prev];
                if (updated.length > 0 && updated[updated.length - 1]?.role === 'assistant') {
                    updated[updated.length - 1] = { role: 'assistant', content: '' };
                }
                return updated;
            });
            try {
                const result = await askAboutIncident(incidentId, question);
                setAskHistory(prev => {
                    const updated = [...prev];
                    updated[updated.length - 1] = { role: 'assistant', content: result.content, tokens: result.tokens, model: result.model };
                    return updated;
                });
            } catch (fallbackErr: unknown) {
                setAskHistory(prev => {
                    const updated = [...prev];
                    updated[updated.length - 1] = { role: 'assistant', content: `Error: ${fallbackErr instanceof Error ? fallbackErr.message : 'Failed to get response'}` };
                    return updated;
                });
            }
        } finally {
            setAskLoading(false);
            setToolActivity(null);
        }
    }

    async function handleResolveDomain(findingId: string) {
        setDomainLoading(prev => ({ ...prev, [findingId]: true }));
        try {
            const result = await resolveFindingDomain(findingId);
            setDomainResolutions(prev => ({ ...prev, [findingId]: result }));
        } catch (err) {
            console.error('Domain resolution failed:', err);
        } finally {
            setDomainLoading(prev => ({ ...prev, [findingId]: false }));
        }
    }

    async function handleResolveFinding(id: string, status: string, expiresIn?: string, baselineMode?: string) {
        try {
            if (expiresIn) {
                await resolveFindingWithExpiry(id, status, '', { expires_in: expiresIn, baseline_mode: baselineMode });
            } else {
                await resolveFinding(id, status, '', { baseline_mode: baselineMode });
            }
            setAllowDropdownOpen(null);
            await fetchIncident();
        } catch (err) {
            console.error('Failed to resolve finding:', err);
        }
    }

    async function handleAllowDirectory(dirPath: string, _detectionId: string, aiType: string) {
        const normalizedPath = dirPath.endsWith('/') ? dirPath.slice(0, -1) : dirPath;
        try {
            await createBaseline({
                signal_type: 'file_pattern',
                pattern: normalizedPath + '/**',
                ai_type: aiType,
            });
            // Retroactively resolve matching findings in this incident
            const prefix = normalizedPath + '/';
            const matchingIds = findings
                .filter(f =>
                    f.status === 'pending' &&
                    (aiType === '' || String((f.context as Record<string, unknown>)?.ai_type ?? '') === aiType) &&
                    typeof (f.context as Record<string, unknown>)?.file_path === 'string' &&
                    ((f.context as Record<string, unknown>).file_path as string).startsWith(prefix)
                )
                .map(f => f.id);
            await Promise.allSettled(matchingIds.map(id => resolveFinding(id, 'allowed', '')));
            setDirAllowTarget(null);
            await fetchIncident();
        } catch (err) {
            console.error('Failed to baseline directory:', err);
        }
    }

    if (loading) {
        return (
            <div className="text-center py-12 text-gray-400">
                <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4" />
                <p>Loading incident details...</p>
            </div>
        );
    }

    if (error || !incident) {
        return (
            <div className="text-center py-12">
                <XCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-xl font-semibold mb-2">{error || 'Incident not found'}</h3>
                <Link href="/incidents" className="text-orange-400 hover:text-orange-300">
                    Back to Incidents
                </Link>
            </div>
        );
    }

    const findings = (incident.findings || []).filter((f, i, arr) => arr.findIndex(x => x.id === f.id) === i);
    const timeline = incident.timeline || [];
    const hasTreeData = !!incident.process_tree;
    const hasGraphData = !!(incident.event_graph?.nodes?.length);

    return (
        <div className="space-y-6">
            {/* Back Navigation */}
            <Link
                href="/incidents"
                className="inline-flex items-center space-x-2 text-gray-400 hover:text-white transition-colors"
            >
                <ArrowLeft className="w-4 h-4" />
                <span className="text-sm">Back to Incidents</span>
            </Link>

            {/* ─── Header ──────────────────────────────────────────── */}
            <IncidentHeader
                incident={incident}
                onRefresh={fetchIncident}
                onStatusUpdate={handleStatusUpdate}
                onConfirmAction={setConfirmAction}
            />

            {/* ─── Graph Visualization ─────────────────────────────── */}
            {(hasTreeData || hasGraphData) && (
                <div>
                    <div className="flex items-center gap-2 mb-3">
                        <button
                            onClick={() => setGraphTab('tree')}
                            className={`px-4 py-2 rounded-xl text-sm font-semibold transition-all duration-200 border flex items-center gap-2 ${
                                graphTab === 'tree'
                                    ? 'bg-orange-500/10 border-orange-500/25 text-orange-400 shadow-lg shadow-orange-500/5'
                                    : 'bg-white/[0.04] border-white/10 text-gray-400 hover:text-white hover:bg-white/[0.08] hover:border-white/20'
                            }`}
                        >
                            <Cpu className="w-4 h-4" />
                            Process Tree
                        </button>
                        <button
                            onClick={() => setGraphTab('graph')}
                            className={`px-4 py-2 rounded-xl text-sm font-semibold transition-all duration-200 border flex items-center gap-2 ${
                                graphTab === 'graph'
                                    ? 'bg-orange-500/10 border-orange-500/25 text-orange-400 shadow-lg shadow-orange-500/5'
                                    : 'bg-white/[0.04] border-white/10 text-gray-400 hover:text-white hover:bg-white/[0.08] hover:border-white/20'
                            }`}
                        >
                            <GitBranch className="w-4 h-4" />
                            Event Graph
                        </button>
                    </div>
                    {graphTab === 'tree' ? (
                        <ProcessTreeView tree={incident.process_tree || null} />
                    ) : (
                        <EventGraphView
                            nodes={incident.event_graph?.nodes || []}
                            edges={incident.event_graph?.edges || []}
                        />
                    )}
                </div>
            )}

            {/* ─── Timeline ────────────────────────────────────────── */}
            {timeline.length > 0 && (
                <IncidentTimeline
                    timeline={timeline}
                    startedAt={incident.started_at}
                    endedAt={incident.ended_at}
                />
            )}

            {/* ─── Findings Panel ──────────────────────────────────── */}
            {(() => {
                const activeFindings = findings.filter(f => f.status === 'pending' || f.status === 'open' || f.status === 'investigating');
                const resolvedFindings = findings.filter(f => f.status !== 'pending' && f.status !== 'open' && f.status !== 'investigating');
                return (
                <GlassCard className="overflow-hidden">
                <button
                    onClick={() => setFindingsOpen(!findingsOpen)}
                    className="w-full flex items-center justify-between p-6 hover:bg-white/5 transition-colors"
                >
                    <div className="flex items-center gap-3">
                        <Eye className="w-5 h-5 text-purple-400" />
                        <h2 className="text-lg font-semibold">
                            Findings ({findings.length})
                            {resolvedFindings.length > 0 && activeFindings.length > 0 && (
                                <span className="text-sm font-normal text-dim ml-2">
                                    {activeFindings.length} active, {resolvedFindings.length} resolved
                                </span>
                            )}
                        </h2>
                    </div>
                    <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform ${findingsOpen ? 'rotate-180' : ''}`} />
                </button>
                {findingsOpen && (
                    <div className="px-6 pb-6 space-y-3">
                        {findings.length === 0 ? (
                            <p className="text-dim text-sm py-4">No finding details available</p>
                        ) : (
                            <>
                            {/* Active findings */}
                            {activeFindings.map((f) => {
                                const fSevConfig = severityConfig[f.severity] || severityConfig.medium;
                                return (
                                    <div key={f.id}>
                                    <div className="flex items-start space-x-3 p-4 bg-black/20 rounded-lg border border-white/5 hover:border-white/10 transition-colors">
                                        <div className={`p-1.5 rounded ${fSevConfig.bg} flex-shrink-0`}>
                                            <Shield className={`w-4 h-4 ${fSevConfig.text}`} />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center space-x-2 mb-1">
                                                <span className="text-sm font-medium text-white">{f.title}</span>
                                                <span className={`px-1.5 py-0.5 rounded text-[10px] border ${fSevConfig.bg} ${fSevConfig.border} ${fSevConfig.text}`}>
                                                    {f.severity.toUpperCase()}
                                                </span>
                                                <span className="text-xs text-dim">{(f.confidence * 100).toFixed(0)}%</span>
                                            </div>
                                            <ExpandableText text={f.summary} maxLines={2} className="text-xs text-gray-400 mb-1" />
                                            {/* Network destination — always visible for exfil/network findings */}
                                            {f.context && (f.context.dst_ip || f.context.domain) ? (() => {
                                                const res = domainResolutions[f.id];
                                                const displayDomain = f.context.domain as string || res?.domains?.[0] || res?.reverse_dns || '';
                                                const asnName = f.context.asn_name as string || res?.asn_name || '';
                                                const bgpPrefix = f.context.bgp_prefix as string || res?.bgp_prefix || '';
                                                const resolved = !!res;
                                                return (
                                                    <div className="flex items-center gap-1.5 text-xs mb-1 flex-wrap">
                                                        <Globe className="w-3 h-3 text-cyan-400/70" />
                                                        <span className="font-mono text-cyan-400">
                                                            {displayDomain ? `${displayDomain} (${f.context.dst_ip}:${f.context.dst_port})` : `${f.context.dst_ip}:${f.context.dst_port}`}
                                                        </span>
                                                        {asnName && <span className="text-gray-400">({asnName})</span>}
                                                        {bgpPrefix && <span className="text-dim font-mono">{bgpPrefix}</span>}
                                                        {!displayDomain && !resolved && (
                                                            <button
                                                                onClick={(e) => { e.stopPropagation(); handleResolveDomain(f.id); }}
                                                                disabled={domainLoading[f.id]}
                                                                className="text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 hover:border-cyan-500/35 px-2.5 py-0.5 rounded-lg transition-all duration-200 disabled:opacity-50 text-[11px] font-medium"
                                                            >
                                                                {domainLoading[f.id] ? 'Resolving...' : 'Find Domain'}
                                                            </button>
                                                        )}
                                                        {!displayDomain && resolved && (
                                                            <span className="text-dim text-[11px]">No domain found</span>
                                                        )}
                                                        {res?.source && <span className="text-dim text-[11px]">via {res.source}</span>}
                                                    </div>
                                                );
                                            })() : null}
                                            {/* Context details */}
                                            {f.context && <FindingContext context={f.context} />}
                                            <div className="flex items-center space-x-3 text-xs text-dim">
                                                <span className="font-mono">{f.detection_id}</span>
                                                <span>{new Date(f.timestamp).toLocaleString()}</span>
                                            </div>
                                        </div>
                                        <div className="flex flex-col gap-1.5 flex-shrink-0">
                                            <Link
                                                href={`/findings?finding=${encodeURIComponent(f.id)}`}
                                                className="px-3.5 py-1.5 bg-purple-500/10 border border-purple-500/25 hover:bg-purple-500/20 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/5 text-purple-400 rounded-xl text-xs font-semibold transition-all duration-200 text-center flex items-center justify-center gap-1.5"
                                            >
                                                <Eye className="w-3.5 h-3.5" />
                                                View
                                            </Link>
                                            <div className="relative">
                                                <button
                                                    onClick={() => setAllowDropdownOpen(allowDropdownOpen === f.id ? null : f.id)}
                                                    className="px-3.5 py-1.5 bg-green-500/10 border border-green-500/25 hover:bg-green-500/20 hover:border-green-500/40 text-green-400 rounded-xl text-xs font-semibold transition-all duration-200 flex items-center justify-center gap-1"
                                                >
                                                    Allow
                                                    <ChevronDown className="w-2.5 h-2.5" />
                                                </button>
                                                {allowDropdownOpen === f.id && (
                                                    <div className="absolute right-0 top-full mt-1 w-48 bg-[#1a1f2e] border border-white/10 rounded-lg shadow-2xl z-50 overflow-hidden">
                                                        {(() => {
                                                            const ctx = f.context as Record<string, unknown>;
                                                            const signalType = ctx?.signal_type as string | undefined;
                                                            const isCommand = signalType === 'command' || signalType === 'escalation_cmd' || signalType === 'persistence_cmd';
                                                            const isFile = signalType === 'file_activity' || signalType === 'file_pattern' || signalType === 'credential_file' || signalType === 'code_tamper' || signalType === 'file_write_burst' || signalType === 'persistence_path';
                                                            const isNetwork = signalType === 'network_dest' || signalType === 'dns_domain';
                                                            const hasBinary = !!(ctx?.binary || ctx?.comm);
                                                            const hasFile = !!(ctx?.file_path);
                                                            const domain = ctx?.domain as string | undefined;
                                                            if (isNetwork) return (
                                                                <>
                                                                    {domain && (
                                                                        <button onClick={async () => { try { await addSafeDomain(domain, `Allowed from finding ${f.id}`); handleResolveFinding(f.id, 'allowed'); } catch (e) { console.error(e); } }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                            <div className="flex items-center gap-1.5 text-[11px] text-green-300"><Globe className="w-2.5 h-2.5" />Add {domain} to Safe Domains</div>
                                                                        </button>
                                                                    )}
                                                                    <button onClick={() => { setAllowTarget({ id: f.id, label: 'Allow Network Destination' }); setAllowDuration(''); setAllowDropdownOpen(null); }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                        <div className="flex items-center gap-1.5 text-[11px] text-cyan-300"><Shield className="w-2.5 h-2.5" />Allow Network Destination</div>
                                                                    </button>
                                                                </>
                                                            );
                                                            if (isCommand || (!isFile && hasBinary)) return (
                                                                <>
                                                                    <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'binary', label: 'Allow Binary' }); setAllowDuration(''); setAllowDropdownOpen(null); }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                        <div className="flex items-center gap-1.5 text-[11px] text-orange-300"><Shield className="w-2.5 h-2.5" />Allow Binary</div>
                                                                    </button>
                                                                    <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'command', label: 'Allow Command' }); setAllowDuration(''); setAllowDropdownOpen(null); }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                        <div className="flex items-center gap-1.5 text-[11px] text-teal-300"><Terminal className="w-2.5 h-2.5" />Allow Command</div>
                                                                    </button>
                                                                </>
                                                            );
                                                            if (isFile || hasFile) return (
                                                                <>
                                                                    <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'file', label: 'Allow File' }); setAllowDuration(''); setAllowDropdownOpen(null); }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                        <div className="flex items-center gap-1.5 text-[11px] text-blue-300"><FileText className="w-2.5 h-2.5" />Allow File</div>
                                                                    </button>
                                                                    <Link href="/baselines?tab=files" onClick={() => setAllowDropdownOpen(null)} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors block">
                                                                        <div className="flex items-center gap-1.5 text-[11px] text-sky-300"><FolderOpen className="w-2.5 h-2.5" />Allow Directory from Baselines</div>
                                                                    </Link>
                                                                </>
                                                            );
                                                            return (
                                                                <button onClick={() => { setAllowTarget({ id: f.id, label: 'Allow Finding' }); setAllowDuration(''); setAllowDropdownOpen(null); }} className="w-full text-left px-3 py-1.5 hover:bg-white/5 transition-colors">
                                                                    <div className="flex items-center gap-1.5 text-[11px] text-white/80"><Shield className="w-2.5 h-2.5" />Allow</div>
                                                                </button>
                                                            );
                                                        })()}
                                                    </div>
                                                )}
                                            </div>
                                            <button
                                                onClick={() => handleResolveFinding(f.id, 'dismissed')}
                                                className="px-3.5 py-1.5 bg-gray-500/10 border border-gray-500/25 hover:bg-gray-500/20 hover:border-gray-500/40 text-gray-400 rounded-xl text-xs font-semibold transition-all duration-200 flex items-center justify-center gap-1.5"
                                            >
                                                <XCircle className="w-3.5 h-3.5" />
                                                Dismiss
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                );
                            })}

                            {activeFindings.length === 0 && resolvedFindings.length > 0 && (
                                <div className="text-center py-4">
                                    <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                                    <p className="text-sm text-gray-400">All findings in this incident have been resolved</p>
                                </div>
                            )}

                            {/* Resolved/allowed findings — collapsed by default */}
                            {resolvedFindings.length > 0 && (
                                <details className="group">
                                    <summary className="cursor-pointer flex items-center gap-2 text-xs text-dim hover:text-gray-400 transition-colors py-2 border-t border-white/5 mt-2">
                                        <ChevronDown className="w-3 h-3 transition-transform group-open:rotate-180" />
                                        <span>{resolvedFindings.length} resolved/allowed finding{resolvedFindings.length !== 1 ? 's' : ''}</span>
                                    </summary>
                                    <div className="space-y-2 mt-2 opacity-60">
                                        {resolvedFindings.map((f) => {
                                            const fSevConfig = severityConfig[f.severity] || severityConfig.medium;
                                            const stConfig = statusConfig[f.status];
                                            return (
                                                <div key={f.id} className="flex items-start space-x-3 p-3 bg-black/10 rounded-lg border border-white/5">
                                                    <div className="p-1.5 rounded bg-gray-500/10 flex-shrink-0">
                                                        <Shield className="w-4 h-4 text-dim" />
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="flex items-center space-x-2 mb-1">
                                                            <span className="text-sm font-medium text-gray-400 line-through decoration-gray-600">{f.title}</span>
                                                            <span className={`px-1.5 py-0.5 rounded text-[10px] border ${stConfig?.bg || 'bg-gray-500/10 border-gray-500/30'} ${stConfig?.color || 'text-gray-400'}`}>
                                                                {stConfig?.label || f.status}
                                                            </span>
                                                        </div>
                                                        <p className="text-xs text-dim mb-1">{f.summary}</p>
                                                        <div className="flex items-center space-x-3 text-xs text-dim">
                                                            <span className="font-mono">{f.detection_id}</span>
                                                            <span>{new Date(f.timestamp).toLocaleString()}</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            );
                                        })}
                                    </div>
                                </details>
                            )}
                            </>
                        )}
                    </div>
                )}
                </GlassCard>
                );
            })()}

            {/* ─── AI Analysis ─────────────────────────────────────── */}
            {/* ─── AI Analysis ──────────────────────────────────────────────────── */}
            <div className="relative overflow-hidden rounded-3xl border-2 border-white/[0.07] bg-[#0d1117]/80 backdrop-blur-md shadow-lg shadow-black/20">
                {/* Top radial glow */}
                <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, rgba(6,182,212,0.05), transparent 55%)' }} />
                <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, rgba(6,182,212,0.18), transparent 90%)' }} />

                {/* Header */}
                <button
                    onClick={() => setAiOpen(!aiOpen)}
                    className="relative w-full flex items-center justify-between px-6 py-4 hover:bg-white/[0.02] transition-colors"
                >
                    <div className="flex items-center gap-3">
                        <Bot className="w-5 h-5 text-cyan-400" />
                        <span className="text-base font-semibold text-white">AI Analysis</span>
                        {aiExplanation?.risk_score != null && aiExplanation.risk_score > 0 && (
                            <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                                aiExplanation.risk_score >= 9 ? 'bg-red-500/15 text-red-400 border-red-500/30' :
                                aiExplanation.risk_score >= 7 ? 'bg-orange-500/15 text-orange-400 border-orange-500/30' :
                                aiExplanation.risk_score >= 4 ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' :
                                'bg-green-500/15 text-green-400 border-green-500/30'
                            }`}>
                                Risk {aiExplanation.risk_score}/10
                            </span>
                        )}
                    </div>
                    <ChevronDown className={`w-4 h-4 text-dim transition-transform duration-300 ${aiOpen ? 'rotate-180' : ''}`} />
                </button>

                {aiOpen && (
                    <div className="relative px-6 pb-6 space-y-4">
                        {/* Q&A quick-suggest + input */}
                        <div className="space-y-3">
                            <div className="flex flex-wrap gap-2">
                                {['Is this a false positive?', 'What process started this?', 'Which credentials are at risk?', 'Show network destinations', 'What should I investigate first?'].map((q) => (
                                    <button
                                        key={q}
                                        onClick={() => handleAskQuestion(q)}
                                        disabled={askLoading}
                                        className="px-3.5 py-1.5 text-xs font-medium bg-white/[0.04] border border-white/10 rounded-full text-gray-400 hover:bg-cyan-500/10 hover:border-cyan-500/25 hover:text-cyan-400 hover:shadow-md hover:shadow-cyan-500/5 transition-all duration-200 disabled:opacity-50"
                                    >
                                        {q}
                                    </button>
                                ))}
                            </div>
                            <div className="flex items-center gap-2">
                                <input
                                    type="text"
                                    value={askInput}
                                    onChange={(e) => setAskInput(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && handleAskQuestion()}
                                    placeholder="Ask about this incident..."
                                    className="flex-1 bg-white/[0.04] border border-white/[0.08] rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-cyan-500/40 focus:bg-white/[0.06] placeholder-gray-600 transition-all"
                                    disabled={askLoading}
                                />
                                <button
                                    onClick={() => handleAskQuestion()}
                                    disabled={!askInput.trim() || askLoading}
                                    className="p-2.5 bg-cyan-500/15 border border-cyan-500/25 text-cyan-400 rounded-xl hover:bg-cyan-500/25 hover:border-cyan-500/40 hover:shadow-lg hover:shadow-cyan-500/5 transition-all duration-200 disabled:opacity-50"
                                >
                                    <Send className="w-4 h-4" />
                                </button>
                            </div>
                        </div>

                        {/* Analyze button */}
                        {!aiExplanation && !aiLoading && (
                            <div className="flex items-center gap-3">
                                <button
                                    onClick={handleExplainIncident}
                                    className="px-5 py-2.5 bg-gradient-to-r from-cyan-500/15 to-blue-500/15 border border-cyan-500/25 text-cyan-400 rounded-xl text-sm font-semibold hover:from-cyan-500/25 hover:to-blue-500/25 hover:border-cyan-500/40 hover:shadow-lg hover:shadow-cyan-500/5 transition-all duration-200 flex items-center gap-2"
                                >
                                    <Sparkles className="w-4 h-4" />
                                    {deepMode ? 'Deep Analysis' : 'Analyze Incident'}
                                </button>
                                <label className="flex items-center gap-2 text-xs text-dim cursor-pointer select-none">
                                    <input
                                        type="checkbox"
                                        checked={deepMode}
                                        onChange={(e) => setDeepMode(e.target.checked)}
                                        className="rounded border-gray-600 bg-white/5 text-cyan-500 focus:ring-cyan-500/30"
                                    />
                                    Deep analysis (more tokens)
                                </label>
                            </div>
                        )}

                        {/* Loading skeleton */}
                        {aiLoading && (
                            <div className="space-y-3">
                                <div className="flex items-center gap-3 mb-1">
                                    <Loader2 className="w-4 h-4 animate-spin text-cyan-400 flex-shrink-0" />
                                    <span className="text-sm text-gray-400">{deepMode ? 'Running deep analysis...' : 'Analyzing incident...'}</span>
                                </div>
                                <div className="animate-pulse space-y-3">
                                    <div className="h-20 bg-white/[0.04] rounded-2xl" />
                                    <div className="h-10 bg-white/[0.03] rounded-xl" />
                                    <div className="h-28 bg-white/[0.04] rounded-2xl" />
                                    <div className="h-20 bg-white/[0.03] rounded-2xl" />
                                </div>
                            </div>
                        )}

                        {/* Error */}
                        {aiError && (
                            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400 flex items-center gap-3">
                                <span className="flex-1">{aiError}</span>
                                <button onClick={handleExplainIncident} className="px-2.5 py-1 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-xs font-medium hover:bg-red-500/20 transition-all">Retry</button>
                            </div>
                        )}

                        {/* Risk gauge + reasoning + section cards */}
                        {aiExplanation && !aiLoading && (() => {
                            const score = aiExplanation.risk_score ?? 0;
                            const riskColor = score >= 9 ? '#f43f5e' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#22c55e';
                            const riskLabel = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
                            const C = 2 * Math.PI * 36;
                            const filled = (score / 10) * C;
                            const sections = parseSections(aiExplanation.content);
                            return (
                                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="space-y-4">
                                    {/* Risk gauge */}
                                    {score > 0 && (
                                        <div className="relative flex items-center gap-5 p-4 rounded-2xl border border-white/[0.07] overflow-hidden">
                                            <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(circle at 10% 50%, ${riskColor}0c, transparent 55%)` }} />
                                            <div className="relative flex-shrink-0">
                                                <svg width="88" height="88" viewBox="0 0 88 88">
                                                    <circle cx="44" cy="44" r="36" fill="none" stroke="white" strokeOpacity="0.06" strokeWidth="6" />
                                                    <motion.circle
                                                        cx="44" cy="44" r="36" fill="none"
                                                        stroke={riskColor} strokeWidth="6" strokeLinecap="round"
                                                        strokeDasharray={`${C}`}
                                                        initial={{ strokeDashoffset: C }}
                                                        animate={{ strokeDashoffset: C - filled }}
                                                        transition={{ duration: 1.2, ease: 'easeOut' }}
                                                        transform="rotate(-90 44 44)"
                                                    />
                                                </svg>
                                                <div className="absolute inset-0 flex flex-col items-center justify-center gap-0.5">
                                                    <span style={{ color: riskColor }}>
                                                        <AnimatedNumber
                                                            value={score}
                                                            format={(n) => `${Math.round(n)}`}
                                                            duration={1.2}
                                                            className="text-2xl font-bold leading-none"
                                                        />
                                                    </span>
                                                    <span className="text-[10px] text-dim">/10</span>
                                                </div>
                                            </div>
                                            <div className="flex-1 min-w-0">
                                                <p className="text-sm font-semibold mb-1" style={{ color: riskColor }}>Risk: {riskLabel}</p>
                                                {aiExplanation.risk_justification && (
                                                    <p className="text-sm text-gray-400 leading-relaxed">{aiExplanation.risk_justification}</p>
                                                )}
                                            </div>
                                        </div>
                                    )}

                                    {/* Reasoning trace */}
                                    {aiExplanation.reasoning && <ReasoningPanel reasoning={aiExplanation.reasoning} />}

                                    {/* Section cards */}
                                    {sections.map((section, i) => {
                                        if (section.title.toLowerCase().startsWith('risk score')) return null;
                                        const cfg = SECTION_CONFIG[section.title as keyof typeof SECTION_CONFIG];
                                        const color = cfg?.color ?? '#6b7280';
                                        const Icon = cfg?.icon ?? FileText;
                                        return (
                                            <motion.div
                                                key={section.title || i}
                                                initial={{ opacity: 0, y: 14 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                transition={{ delay: i * 0.07, duration: 0.35 }}
                                                className="relative rounded-2xl border border-white/[0.07] overflow-hidden"
                                            >
                                                <div className="absolute inset-0 pointer-events-none" style={{ background: `radial-gradient(circle at 0% 0%, ${color}08, transparent 55%)` }} />
                                                <div className="absolute left-0 top-0 bottom-0 w-0.5" style={{ background: color }} />
                                                {section.title && (
                                                    <div className="flex items-center gap-2 px-5 pt-4 pb-2">
                                                        <Icon className="w-4 h-4 flex-shrink-0" style={{ color }} />
                                                        <span className="text-sm font-semibold" style={{ color }}>{section.title}</span>
                                                    </div>
                                                )}
                                                <div className="px-5 pb-4 prose prose-invert prose-sm max-w-none text-gray-300">
                                                    <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents as Record<string, React.ElementType>}>
                                                        {section.body}
                                                    </ReactMarkdown>
                                                </div>
                                            </motion.div>
                                        );
                                    })}

                                    {/* Metadata */}
                                    <div className="flex items-center gap-3 text-xs text-dim pt-1">
                                        <span>Model: {aiExplanation.model}</span>
                                        <span>{aiExplanation.tokens.input} in / {aiExplanation.tokens.output} out tokens</span>
                                        {aiExplanation.cached && <span className="text-cyan-700">cached</span>}
                                        <button
                                            onClick={handleExplainIncident}
                                            className="ml-auto px-3 py-1 bg-white/[0.04] border border-white/[0.08] text-gray-400 rounded-lg text-xs font-medium hover:bg-cyan-500/10 hover:border-cyan-500/20 hover:text-cyan-400 transition-all"
                                        >
                                            Regenerate
                                        </button>
                                    </div>
                                </motion.div>
                            );
                        })()}

                        {/* Chat history */}
                        {askHistory.length > 0 && (
                            <div className="border-t border-white/[0.06] pt-4">
                                <div className="flex items-center justify-between mb-3">
                                    <span className="text-xs text-dim">Conversation{threadId ? ' (persistent)' : ''}</span>
                                    <button
                                        onClick={handleNewConversation}
                                        className="text-xs text-dim hover:text-gray-300 transition-colors"
                                        title="Start a new conversation thread"
                                    >
                                        New conversation
                                    </button>
                                </div>
                                <div className="space-y-3 mb-4 max-h-96 overflow-y-auto">
                                    {askHistory.map((msg, i) => (
                                        <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                                            <div className={`max-w-[85%] px-3 py-2 rounded-xl text-sm ${
                                                msg.role === 'user'
                                                    ? 'bg-orange-500/10 border border-orange-500/20 text-orange-200'
                                                    : 'bg-white/[0.04] border border-white/[0.08] text-gray-300'
                                            }`}>
                                                {msg.role === 'assistant' ? (
                                                    <div className="prose prose-invert prose-sm max-w-none">
                                                        <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents as Record<string, React.ElementType>}>
                                                            {msg.content}
                                                        </ReactMarkdown>
                                                    </div>
                                                ) : (
                                                    <div className="whitespace-pre-wrap">{msg.content}</div>
                                                )}
                                                {msg.tokens && (
                                                    <div className="text-[10px] text-dim mt-1">
                                                        {msg.model} &middot; {msg.tokens.input + msg.tokens.output} tokens
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                    {askLoading && (
                                        <div className="flex justify-start">
                                            <div className="px-3 py-2 bg-white/[0.04] border border-white/[0.08] rounded-xl flex items-center gap-2">
                                                <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                                                {toolActivity && (
                                                    <span className="text-[11px] text-purple-400 font-medium">
                                                        Querying {toolActivity.replace(/_/g, ' ')}...
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <ConfirmDialog
                open={confirmAction !== null}
                onConfirm={() => {
                    if (confirmAction) {
                        handleStatusUpdate(confirmAction.status);
                    }
                    setConfirmAction(null);
                }}
                onCancel={() => setConfirmAction(null)}
                title={confirmAction?.title || ''}
                description={confirmAction?.description || ''}
                confirmLabel={confirmAction?.status === 'resolved' ? 'Resolve' : 'Dismiss'}
                confirmVariant={confirmAction?.variant || 'danger'}
            />

            <ConfirmDialog
                open={allowTarget !== null}
                onConfirm={() => {
                    if (allowTarget) {
                        handleResolveFinding(allowTarget.id, 'allowed', allowDuration || undefined, allowTarget.baselineMode);
                    }
                    setAllowTarget(null);
                    setAllowDuration('');
                }}
                onCancel={() => { setAllowTarget(null); setAllowDuration(''); }}
                title={allowTarget?.label || 'Allow Finding'}
                description="This will mark the finding as allowed and add its pattern to behavioral baselines. Future occurrences will be automatically suppressed."
                confirmLabel="Allow"
                confirmVariant="success"
            >
                <div className="mt-3">
                    <label className="text-xs text-white/50 mb-1.5 block">Baseline duration</label>
                    <div className="flex gap-1.5">
                        {[
                            { value: '', label: 'Permanent' },
                            { value: '7d', label: '7 days' },
                            { value: '30d', label: '30 days' },
                            { value: '90d', label: '90 days' },
                        ].map(opt => (
                            <button
                                key={opt.value}
                                onClick={() => setAllowDuration(opt.value)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                                    allowDuration === opt.value
                                        ? 'bg-green-500/20 border-green-500/40 text-green-400'
                                        : 'bg-white/5 border-white/10 text-white/50 hover:text-white/70 hover:bg-white/10'
                                }`}
                            >
                                {opt.label}
                            </button>
                        ))}
                    </div>
                </div>
            </ConfirmDialog>

            <ConfirmDialog
                open={dirAllowTarget !== null}
                onConfirm={() => {
                    if (dirAllowTarget) handleAllowDirectory(dirAllowTarget.path, dirAllowTarget.detectionId, dirAllowTarget.aiType);
                }}
                onCancel={() => setDirAllowTarget(null)}
                title="Allow Directory"
                description={dirAllowTarget ? `Baseline all files under ${dirAllowTarget.path}/ for ${dirAllowTarget.aiType || 'all AI agents'}. Future findings for files in this directory will be automatically suppressed.` : ''}
                confirmLabel="Allow Directory"
                confirmVariant="success"
            />
        </div>
    );
}

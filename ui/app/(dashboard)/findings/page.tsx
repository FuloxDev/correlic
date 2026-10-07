'use client';

import { useState, useEffect, useRef, useMemo } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, CheckCircle, XCircle, Eye, RefreshCw, Search, X, ChevronDown, ChevronUp, ChevronRight, Bot, ShieldAlert, FolderOpen, FolderClosed, FileText, FolderPlus, Shield, Loader2, Zap, Terminal, Globe, Ban, ShieldOff } from 'lucide-react';
import {
    getFindingsWithTotals, resolveFinding, resolveFindingWithExpiry, createException,
    createBaseline, deleteBaseline, createNeverBaseline, createBlockRule, resolveFindingDomain, addSafeDomain, reconcileFindings, aiAgentDisplayName,
    type Finding, type DomainResolution
} from '@/lib/api-client';
import { ApiError } from '@/lib/api';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { PageHeading } from '@/components/ui/page-heading';
import AnimatedNumber from '@/components/dashboard/AnimatedNumber';

const severityConfig: Record<string, { color: string; hex: string; bg: string; border: string; text: string; icon: React.ElementType }> = {
    critical: { color: 'from-red-500 to-red-600', hex: '#ef4444', bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400', icon: XCircle },
    high: { color: 'from-orange-500 to-orange-600', hex: '#f97316', bg: 'bg-orange-500/10', border: 'border-orange-500/30', text: 'text-orange-400', icon: AlertTriangle },
    medium: { color: 'from-yellow-500 to-yellow-600', hex: '#eab308', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', text: 'text-yellow-400', icon: AlertTriangle },
    low: { color: 'from-amber-500 to-amber-600', hex: '#f59e0b', bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', icon: AlertTriangle },
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

export default function FindingsPage() {
    const [findingsSubTab, setFindingsSubTab] = useState<'pending' | 'blocked' | 'resolved'>('pending');
    const [findings, setFindings] = useState<Finding[]>([]);
    const [totalPending, setTotalPending] = useState(0);
    const [loading, setLoading] = useState(true);
    const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
    const [expandedAgents, setExpandedAgents] = useState<Record<string, boolean>>({});
    const [bulkAllowTarget, setBulkAllowTarget] = useState<string[] | null>(null);
    const [bulkAllowDuration, setBulkAllowDuration] = useState<string>('');
    const [allowDropdownOpen, setAllowDropdownOpen] = useState<string | null>(null); // finding ID with open dropdown
    const [dirAllowTarget, setDirAllowTarget] = useState<{ path: string; detectionId: string; aiType: string; count: number } | null>(null);
    const [allowTarget, setAllowTarget] = useState<{ id: string; baselineMode?: string; label: string } | null>(null);
    const [allowDuration, setAllowDuration] = useState<string>('');
    const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
    const [expandedCmds, setExpandedCmds] = useState<Record<string, boolean>>({});
    const [searchQuery, setSearchQuery] = useState('');
    const [domainResolutions, setDomainResolutions] = useState<Record<string, DomainResolution>>({});
    const [domainLoading, setDomainLoading] = useState<Record<string, boolean>>({});
    const [neverBaselineTarget, setNeverBaselineTarget] = useState<{ signalType: string; pattern: string; findingTitle: string } | null>(null);
    const [nbConflict, setNbConflict] = useState<{ baseline_ids: number[]; pending: { signalType: string; pattern: string; findingTitle: string } } | null>(null);
    const [neverBaselineWorking, setNeverBaselineWorking] = useState(false);
    const [nbDropdownOpen, setNbDropdownOpen] = useState<string | null>(null);

    async function handleResolveDomain(findingId: string) {
        setDomainLoading(prev => ({ ...prev, [findingId]: true }));
        try {
            const result = await resolveFindingDomain(findingId);
            setDomainResolutions(prev => ({ ...prev, [findingId]: result }));
            setFindings(prev => prev.map(f => {
                if (f.id === findingId && result.domains?.length > 0) {
                    return { ...f, context: { ...f.context, domain: result.domains[0], asn_name: result.asn_name || f.context?.asn_name, bgp_prefix: result.bgp_prefix || f.context?.bgp_prefix } };
                }
                return f;
            }));
        } catch (err) {
            console.error('Domain resolution failed:', err);
        } finally {
            setDomainLoading(prev => ({ ...prev, [findingId]: false }));
        }
    }

    async function handleNeverBaselineConfirm() {
        if (!neverBaselineTarget) return;
        setNeverBaselineWorking(true);
        try {
            await createNeverBaseline({ signal_type: neverBaselineTarget.signalType, pattern: neverBaselineTarget.pattern, description: `From finding: ${neverBaselineTarget.findingTitle}` });
            setNeverBaselineTarget(null);
        } catch (err: unknown) {
            if (err instanceof ApiError && err.status === 409) {
                try {
                    const body = JSON.parse(err.body);
                    setNbConflict({ baseline_ids: body.baseline_ids || [], pending: neverBaselineTarget });
                    setNeverBaselineTarget(null);
                    return;
                } catch { /* fall through */ }
            }
            console.error('Never-baseline failed:', err);
        } finally {
            setNeverBaselineWorking(false);
        }
    }

    async function handleNeverBaselineConflictConfirm() {
        if (!nbConflict) return;
        setNeverBaselineWorking(true);
        try {
            for (const id of nbConflict.baseline_ids) {
                try { await deleteBaseline(id); } catch { /* ignore */ }
            }
            await createNeverBaseline({ signal_type: nbConflict.pending.signalType, pattern: nbConflict.pending.pattern, description: `From finding: ${nbConflict.pending.findingTitle}` });
            setNbConflict(null);
        } catch (err) {
            console.error('Never-baseline retry failed:', err);
        } finally {
            setNeverBaselineWorking(false);
        }
    }

    function toggleGroup(id: string) {
        setExpandedGroups(prev => ({ ...prev, [id]: !prev[id] }));
    }

    function toggleAgent(agent: string) {
        setExpandedAgents(prev => ({ ...prev, [agent]: prev[agent] === undefined ? false : !prev[agent] }));
    }

    function togglePath(key: string) {
        setExpandedPaths(prev => ({ ...prev, [key]: !prev[key] }));
    }

    type PathNode = {
        name: string;
        fullPath: string;
        findings: Finding[];
        children: PathNode[];
        totalFindings: number;
        pendingCount: number;
    };

    // Extract the registrable parent domain from a full subdomain.
    // "137.66.149.34.bc.googleusercontent.com" → "googleusercontent.com"
    // "ec2-35-174-255-222.compute-1.amazonaws.com" → "amazonaws.com"
    // "api.openai.com" → "openai.com"
    // "google.com" → null (already a parent)
    function extractParentDomain(domain: string): string | null {
        const parts = domain.split('.');
        if (parts.length <= 2) return null; // already a TLD like "google.com"
        // Handle special TLDs: .co.uk, .com.au, .co.jp, etc.
        const specialTLDs = ['co.uk', 'com.au', 'co.jp', 'com.br', 'co.in', 'com.cn'];
        const lastTwo = parts.slice(-2).join('.');
        if (specialTLDs.includes(lastTwo) && parts.length > 3) {
            return parts.slice(-3).join('.');
        }
        // Standard: take last 2 parts (e.g., "amazonaws.com")
        return parts.slice(-2).join('.');
    }

    // Extract the actual user command from shell wrapper boilerplate (client-side).
    // Handles Claude Code pattern: bash -c "source ... && eval 'cd /path && actual_command'"
    function extractDisplayCommand(cmdline: string): string {
        // Extract eval '...' content
        for (const prefix of ["eval '", 'eval "']) {
            const idx = cmdline.indexOf(prefix);
            if (idx < 0) continue;
            const rest = cmdline.substring(idx + prefix.length);
            const closeChar = prefix === "eval '" ? "'" : '"';
            const endIdx = rest.indexOf(closeChar);
            let evalContent = endIdx > 0 ? rest.substring(0, endIdx) : rest.replace(/['"\s]+$/, '');
            // Strip "cd /path && " prefix
            const cdMatch = evalContent.match(/^cd\s+\S+\s*&&\s*(.*)/);
            if (cdMatch) return cdMatch[1];
            return evalContent;
        }
        // No eval found — if it has && and -c, take last non-boilerplate segment
        if (cmdline.includes(' -c ') && cmdline.includes('&&')) {
            const parts = cmdline.split('&&');
            for (let i = parts.length - 1; i >= 0; i--) {
                const part = parts[i].trim().replace(/['"]+$/, '');
                if (part.length > 3 && !part.startsWith('source ') && !part.startsWith('shopt ') && part !== 'true') {
                    const cdMatch = part.match(/^cd\s+\S+\s*&&\s*(.*)/);
                    if (cdMatch) return cdMatch[1];
                    return part;
                }
            }
        }
        return cmdline;
    }

    function buildPathTree(groupFindings: Finding[]): PathNode[] {
        function extractPath(summary: string): string | null {
            const accessMatch = summary.match(/accessed\s+(\/\S+)/);
            if (accessMatch) return accessMatch[1];
            return null;
        }

        const pathFindings: { path: string; finding: Finding }[] = [];
        const otherFindings: Finding[] = [];

        for (const f of groupFindings) {
            const p = extractPath(f.summary);
            if (p) {
                pathFindings.push({ path: p, finding: f });
            } else {
                otherFindings.push(f);
            }
        }

        if (pathFindings.length === 0 && otherFindings.length === groupFindings.length) {
            return [];
        }

        type TrieNode = { children: Map<string, TrieNode>; findings: Finding[] };
        const trie: TrieNode = { children: new Map(), findings: [] };

        for (const { path, finding } of pathFindings) {
            const segments = path.split('/').filter(Boolean);
            let node = trie;
            for (const seg of segments) {
                if (!node.children.has(seg)) {
                    node.children.set(seg, { children: new Map(), findings: [] });
                }
                node = node.children.get(seg)!;
            }
            node.findings.push(finding);
        }

        function trieToNodes(node: TrieNode, prefix: string): PathNode[] {
            const result: PathNode[] = [];
            for (const [name, child] of node.children.entries()) {
                let collapsedName = name;
                let current = child;
                let currentPath = prefix + '/' + name;

                while (current.children.size === 1 && current.findings.length === 0) {
                    const [nextName, nextChild] = [...current.children.entries()][0];
                    collapsedName += '/' + nextName;
                    currentPath += '/' + nextName;
                    current = nextChild;
                }

                const childNodes = trieToNodes(current, currentPath);
                const ownFindings = current.findings;
                const totalFindings = ownFindings.length + childNodes.reduce((s, c) => s + c.totalFindings, 0);
                const pendingCount = ownFindings.filter(f => f.status === 'pending').length + childNodes.reduce((s, c) => s + c.pendingCount, 0);

                result.push({ name: collapsedName, fullPath: currentPath, findings: ownFindings, children: childNodes, totalFindings, pendingCount });
            }
            result.sort((a, b) => {
                const aIsDir = a.children.length > 0 ? 0 : 1;
                const bIsDir = b.children.length > 0 ? 0 : 1;
                if (aIsDir !== bIsDir) return aIsDir - bIsDir;
                return a.name.localeCompare(b.name);
            });
            return result;
        }

        const tree = trieToNodes(trie, '');

        for (const f of otherFindings) {
            tree.push({ name: f.summary, fullPath: '__other__' + f.id, findings: [f], children: [], totalFindings: 1, pendingCount: f.status === 'pending' ? 1 : 0 });
        }

        return tree;
    }

    function getAllFindingIds(node: PathNode): string[] {
        const ids = node.findings.filter(f => f.status === 'pending').map(f => f.id);
        for (const child of node.children) {
            ids.push(...getAllFindingIds(child));
        }
        return ids;
    }

    const didReconcileRef = useRef(false);

    useEffect(() => {
        if (didReconcileRef.current) return;
        didReconcileRef.current = true;
        reconcileFindings().catch(() => {});
        fetchData();
    }, []);

    async function fetchData() {
        try {
            setLoading(true);
            const findingsResp = await getFindingsWithTotals({ limit: 2000, since: '2000-01-01T00:00:00Z' }).catch(() => ({ findings: [], count: 0, total: 0, total_pending: 0 }));
            setFindings(findingsResp.findings || []);
            setTotalPending(findingsResp.total_pending || 0);
        } catch (err) {
            console.error('Failed to fetch findings:', err);
        } finally {
            setLoading(false);
        }
    }

    async function handleBlockFromFinding(f: Finding) {
        const ctx = f.context || {} as Record<string, unknown>;
        let signalType = ''
        let pattern = ''

        if (f.detection_id.includes('network') || f.detection_id.includes('exfil')) {
            signalType = 'net_connect'
            pattern = ctx.dst_ip ? `${ctx.dst_ip}:${ctx.dst_port || 443}` : ''
        } else if (f.detection_id.includes('command') || f.detection_id.includes('exec') || f.detection_id.includes('persistence') || f.detection_id.includes('privilege') || f.detection_id.includes('discovery')) {
            signalType = 'process_exec'
            pattern = (ctx.binary as string) || ''
        } else if (f.detection_id.includes('file') || f.detection_id.includes('credential')) {
            signalType = 'file_open'
            pattern = (ctx.pattern as string) || (ctx.file_path as string) || ''
        }

        if (!signalType || !pattern) return

        try {
            await createBlockRule({ signal_type: signalType, pattern, description: `Blocked from finding: ${f.title}` })
            // Refresh findings to reflect the new block rule
            fetchData()
        } catch (err) {
            console.error('Failed to create block rule:', err)
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
            await fetchData();
        } catch (err) {
            console.error('Failed to resolve finding:', err);
        }
    }

    async function runBatched<T>(items: T[], fn: (item: T) => Promise<unknown>, batchSize = 5): Promise<{ succeeded: number; failed: number }> {
        let succeeded = 0;
        let failed = 0;
        for (let i = 0; i < items.length; i += batchSize) {
            const batch = items.slice(i, i + batchSize);
            const results = await Promise.allSettled(batch.map(fn));
            for (const r of results) {
                if (r.status === 'fulfilled') succeeded++;
                else failed++;
            }
        }
        return { succeeded, failed };
    }

    async function handleBulkAllow(findingIds: string[], expiresIn?: string) {
        const resolveOne = expiresIn
            ? (id: string) => resolveFindingWithExpiry(id, 'allowed', '', { expires_in: expiresIn })
            : (id: string) => resolveFinding(id, 'allowed', '');
        const { failed } = await runBatched(findingIds, resolveOne);
        if (failed > 0) console.error(`Failed to allow ${failed} of ${findingIds.length} findings`);
        await fetchData();
    }

    async function handleBulkDismiss(findingIds: string[]) {
        const { failed } = await runBatched(findingIds, (id) => resolveFinding(id, 'dismissed', ''));
        if (failed > 0) console.error(`Failed to dismiss ${failed} of ${findingIds.length} findings`);
        await fetchData();
    }

    async function handleAllowDirectory(dirPath: string, _detectionId: string, aiType: string) {
        const normalizedPath = dirPath.endsWith('/') ? dirPath.slice(0, -1) : dirPath;
        try {
            // Create a cross-rule file_pattern baseline (suppresses ALL file-related detection rules)
            await createBaseline({
                signal_type: 'file_pattern',
                pattern: normalizedPath + '/**',
                ai_type: aiType,
            });
            // Retroactively resolve all pending findings under this directory (any detection rule)
            const prefix = normalizedPath + '/';
            const matchingIds = findings
                .filter(f =>
                    f.status === 'pending' &&
                    (aiType === '' || String((f.context as Record<string, unknown>)?.ai_type ?? '') === aiType) &&
                    typeof (f.context as Record<string, unknown>)?.file_path === 'string' &&
                    ((f.context as Record<string, unknown>).file_path as string).startsWith(prefix)
                )
                .map(f => f.id);
            if (matchingIds.length > 0) {
                await handleBulkAllow(matchingIds);
            }
            await fetchData();
        } catch (err) {
            console.error('Failed to create directory baseline:', err);
        }
    }

    const pendingFindings = findings.filter(f => (f.status === 'pending' || f.status === 'investigating') && f.context?.action !== 'blocked');
    const blockedFindings = findings.filter(f => f.status === 'blocked' || f.context?.action === 'blocked');
    const resolvedFindings = findings.filter(f => f.status === 'allowed' || f.status === 'dismissed' || f.status === 'resolved' || f.status === 'auto_resolved');
    const visibleFindings = findingsSubTab === 'pending' ? pendingFindings : findingsSubTab === 'blocked' ? blockedFindings : resolvedFindings;

    type FindingGroup = { detection_id: string; title: string; severity: string; findings: Finding[]; pendingIds: string[] };
    type AgentGroup = { ai_type: string; groups: FindingGroup[]; pendingIds: string[] };

    // Human-readable detection rule names for group headings
    const ruleDisplayNames: Record<string, string> = {
        'ai.command_activity': 'AI Command Activity',
        'ai.file_activity': 'AI File Activity',
        'ai.credential_access': 'AI Credential Access',
        'ai.unauthorized_exec': 'AI Unauthorized Execution',
        'ai.excessive_writes': 'AI Excessive File Writes',
        'ai.data_exfiltration': 'AI Data Exfiltration',
        'ai.unexpected_network': 'AI Unexpected Network',
        'ai.suspicious_dns': 'AI Suspicious DNS',
        'ai.persistence': 'AI Persistence Attempt',
        'ai.privilege_escalation': 'AI Privilege Escalation',
        'ai.code_tampering': 'AI Code Tampering',
    };

    const agentGroups: AgentGroup[] = (() => {
        const agents = new Map<string, Map<string, FindingGroup>>();
        for (const f of visibleFindings) {
            const aiType = aiAgentDisplayName(f.context?.ai_type ? String(f.context.ai_type) : '');
            if (!agents.has(aiType)) agents.set(aiType, new Map());
            const detectionMap = agents.get(aiType)!;
            const key = f.detection_id;
            if (!detectionMap.has(key)) {
                detectionMap.set(key, { detection_id: key, title: f.title, severity: f.severity, findings: [], pendingIds: [] });
            }
            const g = detectionMap.get(key)!;
            g.findings.push(f);
            if (f.status === 'pending') g.pendingIds.push(f.id);
        }
        const arr: AgentGroup[] = [];
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        for (const [aiType, detectionMap] of agents.entries()) {
            const groupsArr = Array.from(detectionMap.values());
            groupsArr.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));
            const pendingIds = groupsArr.flatMap(g => g.pendingIds);
            arr.push({ ai_type: aiType, groups: groupsArr, pendingIds });
        }
        arr.sort((a, b) => b.pendingIds.length - a.pendingIds.length);
        return arr;
    })();

    // Search filter — applied to agent groups
    const filteredAgentGroups = useMemo(() => {
        if (!searchQuery.trim()) return agentGroups;
        const q = searchQuery.toLowerCase();
        return agentGroups.map(agent => {
            const filteredGroups = agent.groups.map(group => {
                const matchedFindings = group.findings.filter(f =>
                    f.title.toLowerCase().includes(q) ||
                    f.summary.toLowerCase().includes(q) ||
                    f.detection_id.toLowerCase().includes(q) ||
                    f.severity.toLowerCase().includes(q) ||
                    (f.context?.ai_type && String(f.context.ai_type).toLowerCase().includes(q))
                );
                if (matchedFindings.length === 0) return null;
                return { ...group, findings: matchedFindings, pendingIds: matchedFindings.filter(f => f.status === 'pending').map(f => f.id) };
            }).filter(Boolean) as typeof agent.groups;
            if (filteredGroups.length === 0) return null;
            return { ...agent, groups: filteredGroups, pendingIds: filteredGroups.flatMap(g => g.pendingIds) };
        }).filter(Boolean) as typeof agentGroups;
    }, [agentGroups, searchQuery]);

    const allPendingIds = findings.filter(f => f.status === 'pending').map(f => f.id);

    const findingCounts = useMemo(() => ({
        critical: findings.filter(f => f.severity === 'critical' && f.status === 'pending').length,
        high: findings.filter(f => f.severity === 'high' && f.status === 'pending').length,
        medium: findings.filter(f => f.severity === 'medium' && f.status === 'pending').length,
        low: findings.filter(f => f.severity === 'low' && f.status === 'pending').length,
    }), [findings]);

    const totalPendingCount = allPendingIds.length;
    const totalResolvedCount = resolvedFindings.length;
    const totalFindingsCount = findings.length;

    return (
        <div className="space-y-7">
            {/* Header */}
            <PageHeading
                title="Findings"
                subtitle="AI detection engine findings"
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
                {totalPendingCount > 0 && (
                    <span className="flex items-center gap-1.5 text-sm bg-purple-500/10 text-purple-400 px-2.5 py-1 rounded-full border border-purple-500/20">
                        <Zap className="w-3 h-3" />
                        {totalPendingCount} pending{findingCounts.critical > 0 ? ` (${findingCounts.critical} critical)` : ''}
                    </span>
                )}
            </PageHeading>

            {/* Rich Stat Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
                {/* Pending Overview */}
                <motion.div
                    custom={0} variants={cardVariants} initial="hidden" animate="visible"
                    whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                    className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                    style={{ background: 'linear-gradient(to bottom, #a855f70c, #a855f704)', borderColor: '#a855f730' }}
                >
                    <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #a855f70c, transparent 70%)' }} />
                    <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #a855f730, transparent 90%)' }} />
                    <div className="relative flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <div className="p-1.5 rounded-xl" style={{ background: '#a855f715' }}>
                                <ShieldAlert className="w-4 h-4 text-purple-400" />
                            </div>
                            <span className="text-xs font-semibold text-purple-400 opacity-70">Pending</span>
                        </div>
                        <AnimatedNumber value={totalPendingCount} className="text-2xl font-extrabold text-purple-400" />
                    </div>
                    <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                        {totalPendingCount > 0 && (['critical', 'high', 'medium', 'low'] as const).map((sev, i) => {
                            const count = findingCounts[sev];
                            if (count === 0) return null;
                            return (
                                <motion.div
                                    key={sev}
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(count / totalPendingCount) * 100}%` }}
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
                                <span className="text-sm font-semibold text-white">{findingCounts[sev]}</span>
                            </div>
                        ))}
                    </div>
                </motion.div>

                {/* Critical + High */}
                <motion.div
                    custom={1} variants={cardVariants} initial="hidden" animate="visible"
                    whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                    className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                    style={{ background: 'linear-gradient(to bottom, #ef44440c, #ef444404)', borderColor: '#ef444430' }}
                >
                    <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #ef44440c, transparent 70%)' }} />
                    <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #ef444430, transparent 90%)' }} />
                    <div className="relative flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <div className="p-1.5 rounded-xl" style={{ background: '#ef444415' }}>
                                <XCircle className="w-4 h-4 text-red-400" />
                            </div>
                            <span className="text-xs font-semibold text-red-400 opacity-70">Critical & High</span>
                        </div>
                        <AnimatedNumber value={findingCounts.critical + findingCounts.high} className="text-2xl font-extrabold text-red-400" />
                    </div>
                    <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                        {(findingCounts.critical + findingCounts.high) > 0 && (
                            <>
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(findingCounts.critical / (findingCounts.critical + findingCounts.high)) * 100}%` }}
                                    transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#ef4444' }}
                                />
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(findingCounts.high / (findingCounts.critical + findingCounts.high)) * 100}%` }}
                                    transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#f97316' }}
                                />
                            </>
                        )}
                    </div>
                    <div className="relative flex gap-x-3">
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-red-400" />
                            <span className="text-xs text-gray-400">Critical</span>
                            <span className="text-sm font-semibold text-white">{findingCounts.critical}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-orange-400" />
                            <span className="text-xs text-gray-400">High</span>
                            <span className="text-sm font-semibold text-white">{findingCounts.high}</span>
                        </div>
                    </div>
                </motion.div>

                {/* Resolved */}
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
                        <AnimatedNumber value={totalResolvedCount} className="text-2xl font-extrabold text-green-400" />
                    </div>
                    <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                        {totalResolvedCount > 0 && (
                            <>
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(resolvedFindings.filter(f => f.status === 'allowed').length / totalResolvedCount) * 100}%` }}
                                    transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#22c55e' }}
                                />
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(resolvedFindings.filter(f => f.status === 'dismissed').length / totalResolvedCount) * 100}%` }}
                                    transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#64748b' }}
                                />
                            </>
                        )}
                    </div>
                    <div className="relative flex gap-x-3">
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-green-400" />
                            <span className="text-xs text-gray-400">Allowed</span>
                            <span className="text-sm font-semibold text-white">{resolvedFindings.filter(f => f.status === 'allowed').length}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-gray-400" />
                            <span className="text-xs text-gray-400">Dismissed</span>
                            <span className="text-sm font-semibold text-white">{resolvedFindings.filter(f => f.status === 'dismissed').length}</span>
                        </div>
                    </div>
                </motion.div>

                {/* Total + Agents */}
                <motion.div
                    custom={3} variants={cardVariants} initial="hidden" animate="visible"
                    whileHover={{ scale: 1.03, y: -2 }} whileTap={{ scale: 0.97 }}
                    className="relative rounded-3xl border-2 p-5 space-y-3 overflow-hidden transition-all duration-300 cursor-default"
                    style={{ background: 'linear-gradient(to bottom, #06b6d40c, #06b6d404)', borderColor: '#06b6d430' }}
                >
                    <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, #06b6d40c, transparent 70%)' }} />
                    <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, #06b6d430, transparent 90%)' }} />
                    <div className="relative flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <div className="p-1.5 rounded-xl" style={{ background: '#06b6d415' }}>
                                <Eye className="w-4 h-4 text-cyan-400" />
                            </div>
                            <span className="text-xs font-semibold text-cyan-400 opacity-70">Total</span>
                        </div>
                        <AnimatedNumber value={totalFindingsCount} className="text-2xl font-extrabold text-white" />
                    </div>
                    <div className="relative h-2 bg-white/[0.06] rounded-full overflow-hidden flex">
                        {totalFindingsCount > 0 && (
                            <>
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(totalPendingCount / totalFindingsCount) * 100}%` }}
                                    transition={{ delay: 0.5, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#a855f7' }}
                                />
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${(totalResolvedCount / totalFindingsCount) * 100}%` }}
                                    transition={{ delay: 0.6, duration: 0.8, ease: 'easeOut' }}
                                    className="h-full" style={{ background: '#22c55e' }}
                                />
                            </>
                        )}
                    </div>
                    <div className="relative flex gap-x-3">
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-purple-400" />
                            <span className="text-xs text-gray-400">Pending</span>
                            <span className="text-sm font-semibold text-white">{totalPendingCount}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-green-400" />
                            <span className="text-xs text-gray-400">Resolved</span>
                            <span className="text-sm font-semibold text-white">{totalResolvedCount}</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                            <Bot className="w-3 h-3 text-cyan-400" />
                            <span className="text-sm font-semibold text-white">{agentGroups.length}</span>
                            <span className="text-xs text-gray-400">agent{agentGroups.length !== 1 ? 's' : ''}</span>
                        </div>
                    </div>
                </motion.div>
            </div>

            {/* Tabs + Search Row */}
            <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                    <button
                        onClick={() => setFindingsSubTab('pending')}
                        className={`px-3 py-1.5 text-sm font-semibold rounded-xl transition-all duration-200 flex items-center gap-1.5 ${findingsSubTab === 'pending'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                        Pending
                        <span className="text-xs tabular-nums opacity-60">{pendingFindings.length}</span>
                    </button>
                    <button
                        onClick={() => setFindingsSubTab('blocked')}
                        className={`px-3 py-1.5 text-sm font-semibold rounded-xl transition-all duration-200 flex items-center gap-1.5 ${findingsSubTab === 'blocked'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                        Blocked
                        {blockedFindings.length > 0 && <span className="text-xs tabular-nums opacity-60">{blockedFindings.length}</span>}
                    </button>
                    <button
                        onClick={() => setFindingsSubTab('resolved')}
                        className={`px-3 py-1.5 text-sm font-semibold rounded-xl transition-all duration-200 flex items-center gap-1.5 ${findingsSubTab === 'resolved'
                            ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                            : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                        }`}
                    >
                        <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                        Resolved
                        <span className="text-xs tabular-nums opacity-60">{resolvedFindings.length}</span>
                    </button>
                </div>

                {/* Search */}
                <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                    <input
                        type="text"
                        placeholder="Search findings..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="pl-8 pr-8 py-2 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500/40 focus:ring-1 focus:ring-purple-500/20 w-56"
                    />
                    {searchQuery && (
                        <button onClick={() => setSearchQuery('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
                            <X className="w-3.5 h-3.5" />
                        </button>
                    )}
                </div>

                {searchQuery && (
                    <span className="text-sm text-gray-500 tabular-nums">
                        {filteredAgentGroups.reduce((s, a) => s + a.groups.reduce((s2, g) => s2 + g.findings.length, 0), 0)} results
                    </span>
                )}
            </div>

            {/* Content */}
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
                        <span>Loading findings...</span>
                    </motion.div>
                ) : findings.length === 0 ? (
                    <motion.div
                        key="empty-all"
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
                            <h3 className="text-xl font-semibold mb-2">No Detection Findings</h3>
                            <p className="text-gray-400">The AI detection engine hasn&apos;t flagged any suspicious behavior yet</p>
                        </GlassCard>
                    </motion.div>
                ) : filteredAgentGroups.length === 0 ? (
                    <motion.div
                        key="empty-filtered"
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
                                {searchQuery ? (
                                    <Search className="w-14 h-14 text-gray-500/50 mx-auto mb-4" />
                                ) : findingsSubTab === 'pending' ? (
                                    <Shield className="w-14 h-14 text-green-400/50 mx-auto mb-4" />
                                ) : (
                                    <Eye className="w-14 h-14 text-gray-500/50 mx-auto mb-4" />
                                )}
                            </motion.div>
                            <h3 className="text-xl font-semibold mb-2">
                                {searchQuery ? 'No Matching Findings'
                                    : findingsSubTab === 'pending' ? 'No Pending Findings'
                                    : 'No Resolved Findings'}
                            </h3>
                            <p className="text-gray-400 max-w-md mx-auto">
                                {searchQuery ? 'Try a different search term'
                                    : findingsSubTab === 'pending' ? 'All findings have been reviewed'
                                    : 'No findings have been allowed or dismissed yet'}
                            </p>
                            {searchQuery && (
                                <button
                                    onClick={() => setSearchQuery('')}
                                    className="mt-4 px-4 py-2 text-sm font-semibold bg-white/5 border border-white/10 rounded-xl text-gray-300 hover:bg-white/10 hover:shadow-lg hover:shadow-white/5 hover:border-white/20 transition-all duration-200"
                                >
                                    Clear search
                                </button>
                            )}
                        </GlassCard>
                    </motion.div>
                ) : (
                    <motion.div
                        key={`list-${findingsSubTab}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="space-y-4"
                    >

                    {/* Bulk Actions Bar */}
                    {findingsSubTab === 'pending' && allPendingIds.length > 0 && !searchQuery && (
                        <motion.div
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.2, duration: 0.3 }}
                        >
                            <div className="relative rounded-2xl border overflow-hidden transition-all duration-300" style={{ background: 'linear-gradient(135deg, #22c55e06, transparent 60%)', borderColor: '#22c55e20' }}>
                                <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 5%, #22c55e30, transparent 95%)' }} />
                                <div className="relative flex items-center justify-between p-3">
                                    <span className="text-xs text-gray-400">
                                        {allPendingIds.length} pending finding{allPendingIds.length !== 1 ? 's' : ''} across {agentGroups.length} agent{agentGroups.length !== 1 ? 's' : ''}
                                    </span>
                                    <button
                                        onClick={() => setBulkAllowTarget(allPendingIds)}
                                        className="px-3 py-1.5 bg-green-500/10 text-green-400 rounded-lg text-xs font-semibold hover:bg-green-500/20 hover:scale-105 transition-all duration-200 flex items-center gap-1.5"
                                    >
                                        <CheckCircle className="w-3.5 h-3.5" />
                                        Allow All ({allPendingIds.length})
                                    </button>
                                </div>
                            </div>
                        </motion.div>
                    )}

                    {/* Grouped Findings by AI Agent */}
                    {filteredAgentGroups.map((agent, agentIdx) => {
                        const isAgentExpanded = expandedAgents[agent.ai_type] ?? true;
                        const agentPendingCount = agent.pendingIds.length;
                        const agentTotalCount = agent.groups.reduce((acc, g) => acc + g.findings.length, 0);

                        return (
                            <motion.div
                                key={agent.ai_type}
                                className="space-y-4"
                                initial={{ opacity: 0, y: 15 }}
                                animate={{ opacity: 1, y: 0 }}
                                transition={{ delay: Math.min(agentIdx * 0.1, 0.4), duration: 0.4 }}
                            >
                                <div
                                    className="group/agent relative rounded-2xl border overflow-hidden transition-all duration-300 cursor-pointer"
                                    style={{
                                        background: agentPendingCount > 0
                                            ? 'linear-gradient(135deg, #06b6d408, transparent 60%)'
                                            : 'linear-gradient(135deg, #64748b06, transparent 60%)',
                                        borderColor: agentPendingCount > 0 ? '#06b6d420' : '#64748b15',
                                    }}
                                    onClick={() => toggleAgent(agent.ai_type)}
                                    onMouseEnter={(e) => { e.currentTarget.style.boxShadow = agentPendingCount > 0 ? '0 8px 30px #06b6d415' : '0 8px 30px #64748b10'; e.currentTarget.style.borderColor = agentPendingCount > 0 ? '#06b6d440' : '#64748b30'; }}
                                    onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = agentPendingCount > 0 ? '#06b6d420' : '#64748b15'; }}
                                >
                                    <div className="absolute inset-x-0 top-0 h-px" style={{ background: agentPendingCount > 0 ? 'linear-gradient(90deg, transparent 5%, #06b6d440, transparent 95%)' : 'linear-gradient(90deg, transparent 5%, #64748b20, transparent 95%)' }} />
                                    <div className="relative flex items-center justify-between p-4">
                                        <div className="flex items-center gap-3">
                                            <div className="p-1.5 rounded-lg" style={{ background: agentPendingCount > 0 ? '#06b6d415' : '#64748b10' }}>
                                                <Bot className={`w-5 h-5 ${agentPendingCount > 0 ? 'text-cyan-400' : 'text-gray-400'}`} />
                                            </div>
                                            <span className="text-[15px] font-semibold text-white/90">{agent.ai_type}</span>
                                            <span className="text-xs text-gray-500 tabular-nums">{agentTotalCount} finding{agentTotalCount !== 1 ? 's' : ''}</span>
                                            {findingsSubTab === 'pending' && agentPendingCount > 0 && (
                                                <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/20">
                                                    {agentPendingCount} pending
                                                </span>
                                            )}
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <ChevronRight className={`w-4 h-4 text-gray-500 transition-transform duration-200 ${isAgentExpanded ? 'rotate-90' : ''}`} />
                                        </div>
                                    </div>
                                </div>

                                {isAgentExpanded && (
                                    <div className="pl-4 md:pl-6 space-y-3 border-l border-white/[0.06] ml-4 md:ml-5 pb-3">
                                        {agent.groups.map((group) => {
                                            const groupKey = agent.ai_type + ':' + group.detection_id;
                                            const config = severityConfig[group.severity] || severityConfig.medium;
                                            const Icon = config.icon;
                                            const pendingCount = group.pendingIds.length;
                                            const totalCount = group.findings.length;
                                            const allowedCount = group.findings.filter(f => f.status === 'allowed').length;
                                            const latestFinding = group.findings[0];
                                            const exampleSummaries = [...new Set(group.findings.slice(0, 3).map(f => f.summary))];
                                            const isRuleExpanded = expandedGroups[groupKey] || false;

                                            return (
                                                <motion.div
                                                    key={groupKey}
                                                    whileHover={{ y: -2 }}
                                                    className="group/rule"
                                                >
                                                    <div
                                                        className="relative rounded-2xl border transition-all duration-300"
                                                        style={{
                                                            background: `linear-gradient(135deg, ${config.hex}08, transparent 60%)`,
                                                            borderColor: `${config.hex}20`,
                                                        }}
                                                        onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 8px 30px ${config.hex}15`; e.currentTarget.style.borderColor = `${config.hex}40`; }}
                                                        onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = `${config.hex}20`; }}
                                                    >
                                                        <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 5%, ${config.hex}40, transparent 95%)` }} />

                                                        <div className="relative p-4">
                                                            {/* Row 1: icon + title + badges */}
                                                            <div className="flex items-center gap-3">
                                                                <div className="p-1.5 rounded-lg shrink-0" style={{ background: `${config.hex}15` }}>
                                                                    <Icon className="w-4 h-4" style={{ color: config.hex }} />
                                                                </div>
                                                                <span className="text-[15px] font-semibold text-white/90 truncate">{ruleDisplayNames[group.detection_id] || group.title}</span>
                                                                <div className="flex items-center gap-1.5 shrink-0 ml-auto">
                                                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider" style={{ color: config.hex, background: `${config.hex}15` }}>
                                                                        {group.severity}
                                                                    </span>
                                                                    {pendingCount > 0 && (
                                                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-500/10 text-purple-300 border border-purple-500/20">
                                                                            {pendingCount} pending
                                                                        </span>
                                                                    )}
                                                                    {allowedCount > 0 && (
                                                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-green-500/10 text-green-300 border border-green-500/20">
                                                                            {allowedCount} allowed
                                                                        </span>
                                                                    )}
                                                                </div>
                                                            </div>

                                                            {/* Row 2: example summaries (collapsed only) */}
                                                            {!isRuleExpanded && exampleSummaries.length > 0 && (
                                                                <p className="text-xs text-gray-500 font-mono mt-2 ml-10 truncate">
                                                                    {exampleSummaries[0]}{totalCount > 1 ? ` (+${totalCount - 1} more)` : ''}
                                                                </p>
                                                            )}

                                                            {/* Row 3: inline stats */}
                                                            <div className="flex items-center gap-3 mt-2.5 ml-10 flex-wrap">
                                                                <span className="text-xs text-gray-400 font-mono">{group.detection_id}</span>
                                                                <span className="text-white/10">|</span>
                                                                <span className="text-xs text-gray-400">
                                                                    <span className="font-semibold text-white/80">{new Set(group.findings.map(f => f.summary)).size}</span> patterns
                                                                </span>
                                                                <span className="text-white/10">|</span>
                                                                <span className="text-xs text-gray-400">
                                                                    <span className="font-semibold text-white/80">{totalCount}</span> total
                                                                </span>
                                                                <span className="text-white/10">|</span>
                                                                <span className="text-xs text-gray-500">{new Date(latestFinding?.created_at).toLocaleString()}</span>
                                                            </div>
                                                        </div>

                                                        {/* Actions — slide up on hover */}
                                                        <div className="flex items-center justify-between px-4 py-2.5 border-t transition-all duration-200 opacity-0 max-h-0 group-hover/rule:opacity-100 group-hover/rule:max-h-16 overflow-hidden" style={{ borderColor: `${config.hex}10` }}>
                                                            <div className="flex items-center gap-2">
                                                                {pendingCount > 0 && (
                                                                    <button
                                                                        onClick={() => handleBulkDismiss(group.pendingIds)}
                                                                        className="px-3 py-1.5 bg-white/5 text-gray-300 rounded-lg text-xs font-semibold hover:bg-white/10 hover:scale-105 transition-all duration-200"
                                                                    >
                                                                        Dismiss
                                                                    </button>
                                                                )}
                                                                {pendingCount === 0 && allowedCount > 0 && (
                                                                    <span className="flex items-center gap-1.5 text-xs text-green-400/70">
                                                                        <CheckCircle className="w-3.5 h-3.5" />
                                                                        Allowed
                                                                    </span>
                                                                )}
                                                            </div>
                                                            <button
                                                                onClick={() => toggleGroup(groupKey)}
                                                                className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 hover:scale-105"
                                                                style={{ color: config.hex, background: `${config.hex}10` }}
                                                            >
                                                                <Eye className="w-3.5 h-3.5" />
                                                                {isRuleExpanded ? 'Collapse' : 'Expand'}
                                                            </button>
                                                        </div>

                                                        {/* Expanded Detailed View — Path Tree */}
                                                        {isRuleExpanded && (() => {
                                                                const tree = buildPathTree(group.findings);

                                                                function renderFinding(f: Finding) {
                                                                    const ctx = (f.context || {}) as Record<string, unknown>;
                                                                    const fHex = severityConfig[f.severity]?.hex || '#64748b';
                                                                    const confidencePct = Math.round((f.confidence || 0) * 100);
                                                                    const confColor = confidencePct >= 85 ? '#ef4444' : confidencePct >= 60 ? '#eab308' : '#64748b';
                                                                    const displayDomain = ctx.dns_domain || ctx.domain;
                                                                    const hasNetwork = ctx.dst_ip || ctx.dst_port;
                                                                    const sensitiveFiles = Array.isArray(ctx.sensitive_files) ? ctx.sensitive_files as string[] : [];
                                                                    return (
                                                                        <div
                                                                            key={f.id}
                                                                            className={`group/finding relative rounded-xl border transition-all duration-300 ${ctx.low_context ? 'opacity-60' : ''}`}
                                                                            style={{ background: `linear-gradient(135deg, ${fHex}06, transparent 60%)`, borderColor: `${fHex}15` }}
                                                                            onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 4px 20px ${fHex}10`; e.currentTarget.style.borderColor = `${fHex}30`; }}
                                                                            onMouseLeave={(e) => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.borderColor = `${fHex}15`; }}
                                                                        >
                                                                            <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent 10%, ${fHex}25, transparent 90%)` }} />
                                                                            <div className="relative px-3 py-2.5">
                                                                                {/* Row 1: severity dot + summary + badges */}
                                                                                <div className="flex items-center gap-2">
                                                                                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: fHex }} />
                                                                                    <p className="text-xs text-gray-200 truncate flex-1" title={f.summary}>{f.summary}</p>
                                                                                    {f.confidence > 0 && (
                                                                                        <span className="text-[10px] font-mono shrink-0 px-1 py-0.5 rounded" style={{ color: confColor, background: `${confColor}15` }}>{confidencePct}%</span>
                                                                                    )}
                                                                                    <span className="px-1 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider shrink-0" style={{ color: fHex, background: `${fHex}15` }}>{f.severity}</span>
                                                                                    {f.status === 'allowed' && <span className="text-[10px] text-green-400 shrink-0 flex items-center gap-0.5"><CheckCircle className="w-2.5 h-2.5" />Allowed</span>}
                                                                                    {f.status === 'dismissed' && <span className="text-[10px] text-gray-500 shrink-0">Dismissed</span>}
                                                                                    {!!(ctx.action === 'blocked' || ctx.blocked) && (
                                                                                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/25 shrink-0 flex items-center gap-0.5">
                                                                                            <ShieldOff className="w-2.5 h-2.5" /> Blocked
                                                                                        </span>
                                                                                    )}
                                                                                    {!!ctx.low_context && <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-500/70 border border-amber-500/20 shrink-0" title="Command-line arguments could not be captured (process exited too fast). Manual investigation recommended.">Low Context</span>}
                                                                                </div>

                                                                                {/* Row 2: command details with expand */}
                                                                                {(ctx.display_cmd || ctx.cmdline) ? (() => {
                                                                                    const rawCmd = String(ctx.cmdline || '');
                                                                                    const displayCmd = String(ctx.display_cmd || extractDisplayCommand(rawCmd) || rawCmd);
                                                                                    const isLong = rawCmd.length > 80;
                                                                                    const isExpanded = expandedCmds[f.id];
                                                                                    return (
                                                                                        <div className="mt-1 ml-3.5">
                                                                                            <p className="text-[11px] text-gray-400 font-mono whitespace-pre-wrap break-all">$ {displayCmd}</p>
                                                                                            {isLong && (
                                                                                                <button
                                                                                                    onClick={(e) => { e.stopPropagation(); setExpandedCmds(prev => ({ ...prev, [f.id]: !prev[f.id] })); }}
                                                                                                    className="text-[10px] text-blue-400/70 hover:text-blue-400 mt-0.5 flex items-center gap-1"
                                                                                                >
                                                                                                    {isExpanded ? '▾ Hide full command' : '▸ Show full command'}
                                                                                                </button>
                                                                                            )}
                                                                                            {isExpanded && (
                                                                                                <pre className="text-[10px] text-gray-300 font-mono mt-1 p-2 bg-black/30 rounded border border-white/5 whitespace-pre-wrap break-all max-h-32 overflow-auto">{rawCmd}</pre>
                                                                                            )}
                                                                                        </div>
                                                                                    );
                                                                                })() : null}
                                                                                {hasNetwork ? (
                                                                                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mt-1 ml-3.5 text-[11px]">
                                                                                        {ctx.dst_ip ? <span className="text-blue-400 font-mono">{String(ctx.dst_ip)}:{String(ctx.dst_port || '?')}</span> : null}
                                                                                        {displayDomain ? <span className="text-cyan-400">{String(displayDomain)}</span> : null}
                                                                                        {!displayDomain && domainResolutions[f.id]?.domains?.length ? (
                                                                                            <span className="text-cyan-400">{domainResolutions[f.id].domains.join(', ')}</span>
                                                                                        ) : null}
                                                                                        {!displayDomain && !domainResolutions[f.id]?.domains?.length ? (
                                                                                            <button
                                                                                                onClick={(e) => { e.stopPropagation(); handleResolveDomain(f.id); }}
                                                                                                disabled={domainLoading[f.id]}
                                                                                                className="text-cyan-500 hover:text-cyan-400 bg-cyan-500/10 hover:bg-cyan-500/20 px-1.5 py-0.5 rounded transition-colors disabled:opacity-50 text-[10px]"
                                                                                            >
                                                                                                {domainLoading[f.id] ? 'Resolving...' : 'Resolve'}
                                                                                            </button>
                                                                                        ) : null}
                                                                                        {ctx.asn_name || domainResolutions[f.id]?.asn_name ? <span className="text-gray-500">({String(ctx.asn_name || domainResolutions[f.id]?.asn_name)})</span> : null}
                                                                                    </div>
                                                                                ) : null}
                                                                                {sensitiveFiles.length > 0 ? (
                                                                                    <div className="mt-1.5 ml-3.5">
                                                                                        <div className="flex items-center gap-1 mb-0.5">
                                                                                            <svg className="w-3 h-3 text-red-400/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                                                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                                                                            </svg>
                                                                                            <span className="text-[10px] text-red-400/70 font-medium">{sensitiveFiles.length} sensitive file{sensitiveFiles.length !== 1 ? 's' : ''}</span>
                                                                                        </div>
                                                                                        <div className="bg-red-500/5 border border-red-500/10 rounded overflow-hidden">
                                                                                            {sensitiveFiles.slice(0, 5).map((fp: string, i: number) => {
                                                                                                const parts = fp.split('/');
                                                                                                const fileName = parts.pop() || fp;
                                                                                                const dirPath = parts.join('/') + '/';
                                                                                                return (
                                                                                                    <div key={i} className={`flex items-center gap-1.5 px-2 py-1 text-[10px] font-mono hover:bg-red-500/10 transition-colors ${i > 0 ? 'border-t border-red-500/5' : ''}`}>
                                                                                                        <span className="truncate" title={fp}><span className="text-gray-600">{dirPath}</span><span className="text-red-300">{fileName}</span></span>
                                                                                                    </div>
                                                                                                );
                                                                                            })}
                                                                                            {sensitiveFiles.length > 5 ? <div className="px-2 py-1 text-[10px] text-red-400/50 border-t border-red-500/5">+{sensitiveFiles.length - 5} more</div> : null}
                                                                                        </div>
                                                                                    </div>
                                                                                ) : null}
                                                                                {Array.isArray(ctx.files) && (ctx.files as string[]).length > 0 ? (
                                                                                    <details className="mt-1 ml-3.5 text-[11px] group">
                                                                                        <summary className="text-yellow-400/80 cursor-pointer hover:text-yellow-300 select-none">
                                                                                            {(ctx.files as string[]).length} file{(ctx.files as string[]).length !== 1 ? 's' : ''} modified
                                                                                            {ctx.file_count && Number(ctx.file_count) > (ctx.files as string[]).length ? ` (${(ctx.files as string[]).length}/${String(ctx.file_count)})` : ''}
                                                                                        </summary>
                                                                                        <div className="mt-1 max-h-36 overflow-y-auto bg-black/30 rounded p-1.5 border border-white/5">
                                                                                            {(ctx.files as string[]).map((fp: string, i: number) => (
                                                                                                <div key={i} className="text-gray-400 font-mono text-[10px] py-0.5 truncate hover:text-gray-200" title={fp}>{fp}</div>
                                                                                            ))}
                                                                                        </div>
                                                                                    </details>
                                                                                ) : null}
                                                                                {!!ctx.dns_query && !hasNetwork ? (
                                                                                    <div className="mt-1 ml-3.5 text-[11px]">
                                                                                        <span className="text-cyan-400 font-mono">{String(ctx.dns_query)}</span>
                                                                                        {ctx.category ? <span className="text-gray-600 ml-1.5">({String(ctx.category)})</span> : null}
                                                                                    </div>
                                                                                ) : null}

                                                                                {/* Row 3: inline metadata */}
                                                                                <div className="flex items-center gap-2 mt-1.5 ml-3.5 flex-wrap">
                                                                                    {ctx.pid ? <span className="text-[10px] text-gray-600">PID {String(ctx.pid)}</span> : null}
                                                                                    {ctx.binary ? <span className="text-[10px] text-gray-600">{String(ctx.binary)}</span> : null}
                                                                                    {ctx.ai_type ? <span className="text-[10px] text-purple-400/60">{aiAgentDisplayName(String(ctx.ai_type))}</span> : null}
                                                                                    {Array.isArray(ctx.mitre_techniques) && (ctx.mitre_techniques as string[]).length > 0 && (
                                                                                        <>
                                                                                            <span className="text-white/8">|</span>
                                                                                            {(ctx.mitre_techniques as string[]).slice(0, 3).map((t: string) => (
                                                                                                <span key={t} className="text-[9px] font-mono text-orange-400/60 bg-orange-500/8 px-1 py-0.5 rounded">{t}</span>
                                                                                            ))}
                                                                                        </>
                                                                                    )}
                                                                                    <span className="text-[10px] text-gray-600 ml-auto tabular-nums">{new Date(f.created_at).toLocaleString()}</span>
                                                                                    {f.incident_id && (
                                                                                        <Link
                                                                                            href={`/incidents/${encodeURIComponent(f.incident_id)}`}
                                                                                            className="inline-flex items-center gap-0.5 text-[10px] text-orange-400 hover:text-orange-300 transition-colors"
                                                                                            onClick={(e) => e.stopPropagation()}
                                                                                        >
                                                                                            <ShieldAlert className="w-2.5 h-2.5" />
                                                                                            Incident
                                                                                        </Link>
                                                                                    )}
                                                                                </div>
                                                                            </div>

                                                                            {/* Actions — appear on hover */}
                                                                            {f.status === 'pending' && (
                                                                                <div className="flex items-center justify-end gap-1 px-3 py-2 border-t transition-all duration-200 opacity-0 max-h-0 group-hover/finding:opacity-100 group-hover/finding:max-h-12 overflow-visible flex-wrap" style={{ borderColor: `${fHex}08` }}>
                                                                                    {(() => {
                                                                                        const ctx = f.context as Record<string, unknown>;
                                                                                        const signalType = ctx?.signal_type as string | undefined;
                                                                                        const isCommand = signalType === 'command' || signalType === 'escalation_cmd' || signalType === 'persistence_cmd';
                                                                                        const isFile = signalType === 'file_activity' || signalType === 'file_pattern' || signalType === 'credential_file' || signalType === 'code_tamper' || signalType === 'file_write_burst' || signalType === 'persistence_path';
                                                                                        const isNetwork = signalType === 'network_dest' || signalType === 'dns_domain';
                                                                                        const hasBinary = !!(ctx?.binary || ctx?.comm);
                                                                                        const hasFile = !!(ctx?.file_path);
                                                                                        const domain = ctx?.domain as string | undefined;
                                                                                        const binary = (ctx?.binary || ctx?.comm) as string | undefined;
                                                                                        const filePath = ctx?.file_path as string | undefined;
                                                                                        const ctxPattern = ctx?.pattern as string | undefined;
                                                                                        const shortBin = binary ? binary.split('/').pop() : undefined;
                                                                                        const shortFile = filePath ? filePath.split('/').pop() : undefined;
                                                                                        const dirPath = filePath ? filePath.substring(0, filePath.lastIndexOf('/')) : undefined;
                                                                                        const btnClass = "px-2 py-1 rounded-lg text-[10px] font-medium hover:scale-105 transition-all duration-200 flex items-center gap-1 whitespace-nowrap";

                                                                                        return (
                                                                                            <>
                                                                                                {/* Allow actions as direct buttons */}
                                                                                                {isNetwork && domain && (
                                                                                                    <button onClick={async () => { try { await addSafeDomain(domain, `Allowed from finding ${f.id}`); handleResolveFinding(f.id, 'allowed'); } catch (e) { console.error(e); } }} className={`${btnClass} bg-green-500/10 text-green-400 border border-green-500/20`}>
                                                                                                        <Globe className="w-2.5 h-2.5" />Safe Domain
                                                                                                    </button>
                                                                                                )}
                                                                                                {isNetwork && domain && (() => {
                                                                                                    const parentDomain = extractParentDomain(domain);
                                                                                                    if (parentDomain && parentDomain !== domain) return (
                                                                                                        <button onClick={async () => { try { await addSafeDomain(parentDomain, `Parent domain allowed from finding ${f.id}`); handleResolveFinding(f.id, 'allowed'); } catch (e) { console.error(e); } }} className={`${btnClass} bg-emerald-500/10 text-emerald-400 border border-emerald-500/20`}>
                                                                                                            <Globe className="w-2.5 h-2.5" />{parentDomain}
                                                                                                        </button>
                                                                                                    );
                                                                                                    return null;
                                                                                                })()}
                                                                                                {isNetwork && (
                                                                                                    <button onClick={() => { setAllowTarget({ id: f.id, label: 'Allow Destination' }); setAllowDuration(''); }} className={`${btnClass} bg-cyan-500/10 text-cyan-400 border border-cyan-500/20`}>
                                                                                                        <Shield className="w-2.5 h-2.5" />Allow Dest
                                                                                                    </button>
                                                                                                )}
                                                                                                {(isCommand || (!isFile && !isNetwork && hasBinary)) && (
                                                                                                    <>
                                                                                                        <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'binary', label: 'Allow Binary' }); setAllowDuration(''); }} className={`${btnClass} bg-orange-500/10 text-orange-400 border border-orange-500/20`}>
                                                                                                            <Shield className="w-2.5 h-2.5" />Allow {shortBin || 'Binary'}
                                                                                                        </button>
                                                                                                        <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'command', label: 'Allow Command' }); setAllowDuration(''); }} className={`${btnClass} bg-teal-500/10 text-teal-400 border border-teal-500/20`}>
                                                                                                            <Terminal className="w-2.5 h-2.5" />Allow Cmd
                                                                                                        </button>
                                                                                                    </>
                                                                                                )}
                                                                                                {(isFile || (!isCommand && !isNetwork && hasFile)) && (
                                                                                                    <>
                                                                                                        <button onClick={() => { setAllowTarget({ id: f.id, baselineMode: 'file', label: 'Allow File' }); setAllowDuration(''); }} className={`${btnClass} bg-blue-500/10 text-blue-400 border border-blue-500/20`}>
                                                                                                            <FileText className="w-2.5 h-2.5" />Allow File
                                                                                                        </button>
                                                                                                        {dirPath && (
                                                                                                            <button onClick={() => handleAllowDirectory(dirPath, f.detection_id, String(ctx?.ai_type || ''))} className={`${btnClass} bg-sky-500/10 text-sky-400 border border-sky-500/20`}>
                                                                                                                <FolderOpen className="w-2.5 h-2.5" />Allow Dir
                                                                                                            </button>
                                                                                                        )}
                                                                                                    </>
                                                                                                )}
                                                                                                {!isNetwork && !isCommand && !isFile && !hasBinary && !hasFile && (
                                                                                                    <button onClick={() => { setAllowTarget({ id: f.id, label: 'Allow' }); setAllowDuration(''); }} className={`${btnClass} bg-green-500/10 text-green-400 border border-green-500/20`}>
                                                                                                        <Shield className="w-2.5 h-2.5" />Allow
                                                                                                    </button>
                                                                                                )}
                                                                                            </>
                                                                                        );
                                                                                    })()}
                                                                                    {/* Block button */}
                                                                                    <button
                                                                                        onClick={() => handleBlockFromFinding(f)}
                                                                                        className="px-2 py-1 rounded-lg text-[10px] font-medium bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 hover:scale-105 transition-all duration-200 flex items-center gap-1"
                                                                                    >
                                                                                        <ShieldOff className="w-2.5 h-2.5" />Block
                                                                                    </button>
                                                                                    {/* Dismiss */}
                                                                                    <button
                                                                                        onClick={() => handleResolveFinding(f.id, 'dismissed')}
                                                                                        className="px-2 py-1 rounded-lg text-[10px] font-medium bg-white/5 text-gray-400 hover:bg-white/10 hover:scale-105 transition-all duration-200"
                                                                                    >
                                                                                        Dismiss
                                                                                    </button>
                                                                                    {/* Investigate */}
                                                                                    <a
                                                                                        href={`/ai?finding=${f.id}`}
                                                                                        className="px-2 py-1 rounded-lg text-[10px] font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 hover:scale-105 transition-all duration-200"
                                                                                    >
                                                                                        Investigate
                                                                                    </a>
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    );
                                                                }

                                                                function renderNode(node: PathNode, depth: number) {
                                                                    const isLeaf = node.children.length === 0;
                                                                    const isOpen = expandedPaths[node.fullPath] || false;
                                                                    const pendingIds = getAllFindingIds(node);

                                                                    return (
                                                                        <div key={node.fullPath} style={{ paddingLeft: depth * 16 }}>
                                                                            <div
                                                                                className="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-white/5 cursor-pointer transition-colors group"
                                                                                onClick={() => togglePath(node.fullPath)}
                                                                            >
                                                                                <div className="flex items-center gap-2 min-w-0">
                                                                                    {isLeaf ? (
                                                                                        <FileText className="w-4 h-4 text-gray-500 flex-shrink-0" />
                                                                                    ) : isOpen ? (
                                                                                        <FolderOpen className="w-4 h-4 text-yellow-500 flex-shrink-0" />
                                                                                    ) : (
                                                                                        <FolderClosed className="w-4 h-4 text-yellow-500/70 flex-shrink-0" />
                                                                                    )}
                                                                                    <span className={`text-sm truncate ${isLeaf ? 'text-gray-300' : 'text-white font-medium'}`}>
                                                                                        {isLeaf ? node.name : node.name + '/'}
                                                                                    </span>
                                                                                    <span className="text-xs text-gray-500 flex-shrink-0">({node.totalFindings})</span>
                                                                                    {node.pendingCount > 0 && (
                                                                                        <span className="px-1.5 py-0.5 text-xs bg-purple-500/20 text-purple-300 rounded border border-purple-500/30 flex-shrink-0">
                                                                                            {node.pendingCount} pending
                                                                                        </span>
                                                                                    )}
                                                                                </div>
                                                                                <div className="flex items-center gap-2">
                                                                                    {!isLeaf && pendingIds.length > 0 && (
                                                                                        <button
                                                                                            onClick={(e) => { e.stopPropagation(); setDirAllowTarget({ path: node.fullPath, detectionId: group.detection_id, aiType: group.findings[0]?.context?.ai_type ? String(group.findings[0].context.ai_type) : '', count: pendingIds.length }); }}
                                                                                            className="px-2 py-1 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 rounded-xl text-xs font-semibold hover:shadow-lg hover:shadow-blue-500/5 hover:border-blue-500/40 transition-all duration-200 opacity-0 group-hover:opacity-100 flex items-center gap-1"
                                                                                        >
                                                                                            <FolderPlus className="w-3 h-3" />
                                                                                            Allow Dir
                                                                                        </button>
                                                                                    )}
                                                                                    {!isLeaf && (
                                                                                        <ChevronRight className={`w-4 h-4 text-gray-500 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                                                                                    )}
                                                                                </div>
                                                                            </div>

                                                                            {isOpen && (
                                                                                <div className="ml-2 border-l border-white/5">
                                                                                    {node.children.map(child => renderNode(child, depth + 1))}
                                                                                    {node.findings.length > 0 && (
                                                                                        <div className="space-y-1.5 py-2" style={{ paddingLeft: (depth + 1) * 16 }}>
                                                                                            {node.findings.map(f => renderFinding(f))}
                                                                                        </div>
                                                                                    )}
                                                                                </div>
                                                                            )}
                                                                        </div>
                                                                    );
                                                                }

                                                                return (
                                                                    <div className="mt-3 mx-4 mb-4 p-3 rounded-xl bg-black/30 border border-white/[0.06]">
                                                                        {tree.length > 0 ? (
                                                                            <div className="space-y-0.5">
                                                                                {tree.map(node => renderNode(node, 0))}
                                                                            </div>
                                                                        ) : (
                                                                            <div className="space-y-2">
                                                                                {group.findings.map(f => renderFinding(f))}
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                );
                                                            })()}
                                                    </div>
                                                </motion.div>
                                            );
                                        })}
                                    </div>
                                )}
                            </motion.div>
                        );
                    })}
                    </motion.div>
                )}
            </AnimatePresence>

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
                open={bulkAllowTarget !== null}
                onConfirm={() => {
                    if (bulkAllowTarget) handleBulkAllow(bulkAllowTarget, bulkAllowDuration || undefined);
                    setBulkAllowTarget(null);
                    setBulkAllowDuration('');
                }}
                onCancel={() => { setBulkAllowTarget(null); setBulkAllowDuration(''); }}
                title="Allow All Findings"
                description={`This will mark ${bulkAllowTarget?.length ?? 0} finding(s) as allowed and add their patterns to behavioral baselines. Future occurrences will be automatically suppressed.`}
                confirmLabel="Allow All"
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
                                onClick={() => setBulkAllowDuration(opt.value)}
                                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all duration-200 border ${
                                    bulkAllowDuration === opt.value
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
                    setDirAllowTarget(null);
                }}
                onCancel={() => setDirAllowTarget(null)}
                title="Allow Entire Directory"
                description={`This will baseline "${dirAllowTarget?.path ?? ''}/**"${dirAllowTarget?.aiType ? ` for ${aiAgentDisplayName(dirAllowTarget.aiType)}` : ''}. All current (${dirAllowTarget?.count ?? 0}) and future file-related findings under this directory will be automatically suppressed.`}
                confirmLabel="Allow Directory"
                confirmVariant="success"
            />

            <ConfirmDialog
                open={neverBaselineTarget !== null}
                onConfirm={handleNeverBaselineConfirm}
                onCancel={() => setNeverBaselineTarget(null)}
                title="Never Baseline This Pattern"
                description={neverBaselineTarget ? `Add "${neverBaselineTarget.pattern}" (${neverBaselineTarget.signalType}) to your organization's Never-Baseline list. The detection engine will always raise an incident for this pattern — it can never be silenced by the learning engine.` : ''}
                confirmLabel={neverBaselineWorking ? 'Adding...' : 'Never Baseline'}
                confirmVariant="danger"
            />

            <ConfirmDialog
                open={nbConflict !== null}
                onConfirm={handleNeverBaselineConflictConfirm}
                onCancel={() => setNbConflict(null)}
                title="Existing Baselines Conflict"
                description={nbConflict ? `${nbConflict.baseline_ids.length} existing baseline${nbConflict.baseline_ids.length !== 1 ? 's' : ''} match this pattern. They must be removed before this rule can be added. Remove them now and proceed?` : ''}
                confirmLabel={neverBaselineWorking ? 'Removing...' : 'Remove Baselines & Add Rule'}
                confirmVariant="danger"
            />
        </div>
    );
}

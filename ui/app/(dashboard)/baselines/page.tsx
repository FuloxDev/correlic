'use client';

import React, { useState, useEffect, useMemo, useRef, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { motion, AnimatePresence } from 'framer-motion';
import { RefreshCw, Filter, Database, FileText, Cpu, Globe, Wifi, ShieldCheck, Bot, UserCheck, ChevronDown, ChevronRight, Folder, Loader2, Plus, Trash2, Search, X, Clock, Terminal, Sparkles, Ban, AlertTriangle, ShieldOff, Eye } from 'lucide-react';
import { getBaselines, getBaselineSummary, getSafeDomains, addSafeDomain, deleteSafeDomain, deleteBaseline, suspendBaseline, confirmBaseline, createBaseline, getBaselineExclusions, deleteBaselineExclusion, getNeverBaselines, createNeverBaseline, deleteNeverBaseline, getBlockRules, createBlockRule, updateBlockRule, deleteBlockRule, getSuppressedSummary, getNoiseFilters, aiAgentDisplayName, AI_AGENT_NAMES, resolveIP, type Baseline, type SafeDomain, type BaselineSummary, type BaselineExclusion, type NeverBaselineEntry, type BlockRule, type SuppressedGroup, type NoiseFilters, type IPEnrichment } from '@/lib/api-client';
import { ApiError } from '@/lib/api';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { PageHeading } from '@/components/ui/page-heading';
import AnimatedNumber from '@/components/dashboard/AnimatedNumber';

const PAGE_SIZE = 100;

const signalTypeConfig: Record<string, { label: string; icon: React.ElementType; color: string; hex: string; bg: string; border: string; suppresses: string; description: string }> = {
    file_pattern: { label: 'File Pattern', icon: FileText, color: 'text-blue-400', hex: '#3b82f6', bg: 'bg-blue-500/10', border: 'border-blue-500/30', suppresses: 'ai.credential_access, ai.excessive_writes', description: 'File access won\'t trigger credential access or excessive write alerts' },
    binary: { label: 'Binary', icon: Cpu, color: 'text-green-400', hex: '#22c55e', bg: 'bg-green-500/10', border: 'border-green-500/30', suppresses: 'ai.unauthorized_exec, ai.container_escape', description: 'Execution of this binary won\'t trigger unauthorized exec or container escape alerts' },
    network_dest: { label: 'Network', icon: Wifi, color: 'text-orange-400', hex: '#f97316', bg: 'bg-orange-500/10', border: 'border-orange-500/30', suppresses: 'ai.data_exfiltration', description: 'Connections to this destination won\'t trigger exfiltration alerts' },
    dns_domain: { label: 'DNS', icon: Globe, color: 'text-purple-400', hex: '#a855f7', bg: 'bg-purple-500/10', border: 'border-purple-500/30', suppresses: 'ai.suspicious_dns', description: 'DNS lookups for this domain won\'t trigger suspicious DNS alerts' },
    container_escape: { label: 'Container', icon: Database, color: 'text-red-400', hex: '#ef4444', bg: 'bg-red-500/10', border: 'border-red-500/30', suppresses: 'ai.container_escape', description: 'Container escape access to this path won\'t trigger alerts' },
    escalation_cmd: { label: 'Escalation', icon: ShieldCheck, color: 'text-yellow-400', hex: '#eab308', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', suppresses: 'ai.privilege_escalation', description: 'This privilege escalation command won\'t trigger alerts' },
    persistence_path: { label: 'Persistence', icon: FileText, color: 'text-pink-400', hex: '#ec4899', bg: 'bg-pink-500/10', border: 'border-pink-500/30', suppresses: 'ai.persistence', description: 'Access to this persistence path won\'t trigger alerts' },
    persistence_cmd: { label: 'Persistence', icon: Cpu, color: 'text-pink-400', hex: '#ec4899', bg: 'bg-pink-500/10', border: 'border-pink-500/30', suppresses: 'ai.persistence', description: 'This persistence command won\'t trigger alerts' },
    code_tamper: { label: 'Code Tamper', icon: FileText, color: 'text-cyan-400', hex: '#06b6d4', bg: 'bg-cyan-500/10', border: 'border-cyan-500/30', suppresses: 'ai.code_tampering', description: 'Modifications to this file won\'t trigger code tampering alerts' },
    file_write_burst: { label: 'Write Burst', icon: FileText, color: 'text-amber-400', hex: '#f59e0b', bg: 'bg-amber-500/10', border: 'border-amber-500/30', suppresses: 'ai.excessive_writes', description: 'Write bursts from this source won\'t trigger excessive write alerts' },
    credential_file: { label: 'Credential', icon: FileText, color: 'text-rose-400', hex: '#f43f5e', bg: 'bg-rose-500/10', border: 'border-rose-500/30', suppresses: 'ai.credential_access', description: 'Access to this credential file won\'t trigger alerts' },
    keyword_heuristic: { label: 'Keyword', icon: Search, color: 'text-indigo-400', hex: '#6366f1', bg: 'bg-indigo-500/10', border: 'border-indigo-500/30', suppresses: 'ai.credential_access', description: 'This keyword pattern won\'t trigger credential access alerts' },
    command: { label: 'Command', icon: Terminal, color: 'text-teal-400', hex: '#2dd4bf', bg: 'bg-teal-500/10', border: 'border-teal-500/30', suppresses: 'ai.command_activity', description: 'This exact command won\'t trigger activity tracking alerts' },
    command_binary: { label: 'Binary', icon: Cpu, color: 'text-green-400', hex: '#22c55e', bg: 'bg-green-500/10', border: 'border-green-500/30', suppresses: 'ai.command_activity', description: 'Any invocation of this binary won\'t trigger activity tracking alerts' },
    command_file: { label: 'Allowed File', icon: FileText, color: 'text-teal-400', hex: '#2dd4bf', bg: 'bg-teal-500/10', border: 'border-teal-500/30', suppresses: 'ai.command_activity', description: 'Commands targeting this file won\'t trigger activity tracking alerts' },
    discovery_cmd: { label: 'Discovery', icon: Search, color: 'text-lime-400', hex: '#84cc16', bg: 'bg-lime-500/10', border: 'border-lime-500/30', suppresses: 'ai.discovery', description: 'This discovery command won\'t trigger reconnaissance alerts' },
    discovery_burst: { label: 'Discovery Burst', icon: Search, color: 'text-lime-400', hex: '#84cc16', bg: 'bg-lime-500/10', border: 'border-lime-500/30', suppresses: 'ai.discovery', description: 'This discovery pattern won\'t trigger burst reconnaissance alerts' },
    file_activity: { label: 'File Activity', icon: FileText, color: 'text-sky-400', hex: '#38bdf8', bg: 'bg-sky-500/10', border: 'border-sky-500/30', suppresses: 'ai.file_activity', description: 'AI file access to this path won\'t trigger activity tracking alerts' },
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

function formatDate(dateStr: string): string {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / 3600000);
    const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (hours < 1) return time;
    if (hours < 24) return `${time} (${hours}h ago)`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`;
    return `${date.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`;
}

/** Shorten an absolute path for display: /home/<user>/... → ~/... */
function shortenPath(path: string): string {
    return path.replace(/^\/home\/[^/]+/, '~')
}

/** Freshness dot color: green < 1h, yellow < 24h, gray otherwise */
function freshnessColor(dateStr: string): string {
    const diff = Date.now() - new Date(dateStr).getTime();
    if (diff < 3600000) return '#22c55e';   // green — last hour
    if (diff < 86400000) return '#eab308';  // yellow — last 24h
    return '#64748b';                        // gray — older
}

// Tree node for nested file baseline display
interface TreeNode {
    name: string         // directory segment name (e.g. "correlic-ui")
    fullPath: string     // full absolute path
    displayPath: string  // shortened (~ prefix)
    children: TreeNode[] // sub-directories
    files: Baseline[]    // leaf files in this exact directory
    totalFiles: number   // recursive file count (for sorting & page header)
    totalHits: number    // recursive hit sum (for sorting)
    directFiles: number  // files in this exact directory only
    directHits: number   // hits from this directory's files only
    maxLastSeen: string  // most recent access across all descendants
    latestFile: string   // basename of the most recently accessed file
    agents: Set<string>  // unique ai_type values from this directory's files only
    globAgents: Set<string> // ai_type values that have a dir/** baseline at this exact level
    hasConfirmed: boolean // true if any direct file is user_confirmed
        dirBaselineId: number | null // id of the /** glob baseline at this directory, if any
    dirBaselineAgent: string // ai_type of the /** glob baseline ("" = all agents)
}

interface TreeRowsProps {
    node: TreeNode
    depth: number
    maxHits: number
    expandedDirs: Set<string>
    setExpandedDirs: React.Dispatch<React.SetStateAction<Set<string>>>
    setSuspendTarget: (id: number) => void
    setDeleteTarget: (id: number | null) => void
    setAddDirTarget: (target: { path: string } | null) => void
    formatDate: (dateStr: string) => string
    formatExpiresAt: (expiresAt?: string, suspendedUntil?: string) => string | null
    freshnessColor: (dateStr: string) => string
    isLast?: boolean
}

// Network baseline grouping types
interface NetworkPortGroup {
    port: number
    portLabel: string
    subnets: NetworkSubnetEntry[]
    totalHits: number
    maxLastSeen: string
    agents: Set<string>
}

// Per-agent grouping of baselines
interface AgentGroup {
    agentKey: string      // raw ai_type value ('' for unscoped)
    agentLabel: string    // display name
    fileTree: TreeNode[]
    networkPortGroups: NetworkPortGroup[]
    totalCount: number
}

interface NetworkSubnetEntry {
    baseline: Baseline
    cidr: string
    port: number
}

const wellKnownPorts: Record<number, string> = {
    22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 853: 'DNS-TLS',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'Alt',
    9090: 'Prometheus', 27017: 'MongoDB', 6443: 'K8s API',
}

function parseCIDRPort(pattern: string): { cidr: string; port: number } {
    const lastColon = pattern.lastIndexOf(':')
    if (lastColon === -1) return { cidr: pattern, port: 0 }
    const maybePort = pattern.substring(lastColon + 1)
    const port = parseInt(maybePort, 10)
    if (isNaN(port) || port < 0 || port > 65535) return { cidr: pattern, port: 0 }
    const cidr = pattern.substring(0, lastColon)
    // IPv4 CIDR like "23.20.208.0/24" — no colons in CIDR part
    if (!cidr.includes(':')) return { cidr, port }
    // IPv6 with CIDR like "2001:db8::/32" — has slash, last segment is port
    if (cidr.includes('/')) return { cidr, port }
    // IPv6 without CIDR — the last segment could be port if the address part is valid
    // Count colons in the cidr part: a real IPv6 has 2-7 colons (or :: shorthand)
    const colonCount = (cidr.match(/:/g) || []).length
    if (colonCount >= 2 || cidr.includes('::')) return { cidr, port }
    // Single colon in cidr: ambiguous, treat whole pattern as CIDR
    return { cidr: pattern, port: 0 }
}

function TreeRows({ node, depth, maxHits, expandedDirs, setExpandedDirs, setSuspendTarget, setDeleteTarget, setAddDirTarget, formatDate, formatExpiresAt, freshnessColor, isLast = false }: TreeRowsProps) {
    const isExpanded = expandedDirs.has(node.fullPath)
    const toggle = (e: React.MouseEvent) => {
        e.stopPropagation()
        setExpandedDirs(prev => {
            const next = new Set(prev)
            if (next.has(node.fullPath)) next.delete(node.fullPath)
            else next.add(node.fullPath)
            return next
        })
    }

    const hitPct = maxHits > 0 ? (node.totalHits / maxHits) * 100 : 0
    const freshColor = node.maxLastSeen ? freshnessColor(node.maxLastSeen) : '#64748b'
    const hasContent = node.children.length > 0 || node.files.length > 0

    return (
        <div className="relative">
            {/* Tree connector lines */}
            {depth > 0 && (
                <>
                    <div
                        className="absolute top-0 border-l border-white/[0.06]"
                        style={{ left: `${depth * 24 + 11}px`, height: isLast ? '18px' : '100%' }}
                    />
                    <div
                        className="absolute top-[18px] border-t border-white/[0.06]"
                        style={{ left: `${depth * 24 + 11}px`, width: '12px' }}
                    />
                </>
            )}

            {/* Directory row */}
            <div
                className={`group flex items-center gap-2.5 h-9 px-3 mx-1 rounded-lg cursor-pointer transition-all duration-200 ${
                    isExpanded
                        ? 'bg-blue-500/[0.06] border border-blue-500/15'
                        : 'hover:bg-white/[0.04] border border-transparent'
                }`}
                style={{ marginLeft: `${depth * 24 + (depth > 0 ? 20 : 0)}px` }}
                onClick={toggle}
            >
                {/* Expand chevron */}
                <motion.div
                    animate={{ rotate: isExpanded ? 90 : 0 }}
                    transition={{ duration: 0.15 }}
                    className={`shrink-0 ${isExpanded ? 'text-blue-400' : 'text-gray-600 group-hover:text-gray-400'}`}
                >
                    <ChevronRight className="w-4 h-4" />
                </motion.div>

                {/* Folder icon */}
                <Folder className={`w-4 h-4 shrink-0 ${isExpanded ? 'text-blue-400' : 'text-gray-500 group-hover:text-blue-400'} transition-colors`} />

                {/* Path name */}
                <span className={`font-mono text-[13px] truncate ${isExpanded ? 'text-blue-300' : 'text-gray-200 group-hover:text-white'} transition-colors`} title={node.fullPath}>
                    {depth === 0 ? node.fullPath : node.name}/
                </span>

                {/* File count pill — shows direct files only */}
                <span className={`shrink-0 px-2 py-0.5 rounded text-xs font-semibold tabular-nums ${
                    node.directFiles > 0
                        ? isExpanded ? 'bg-blue-500/20 text-blue-300' : 'bg-white/[0.06] text-gray-500'
                        : 'bg-transparent text-gray-600'
                }`}>
                    {node.directFiles > 0 ? node.directFiles : ''}
                </span>

                {/* Confirmed badge for manually baselined dirs */}
                {node.hasConfirmed && (
                    <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-green-500/10 text-green-400 border border-green-500/20">
                        <UserCheck className="w-3 h-3" />
                        Confirmed
                    </span>
                )}

                {/* Spacer */}
                <div className="flex-1 min-w-8" />

                {/* Right columns */}
                <div className="shrink-0 flex items-center gap-6">
                    {/* Latest file */}
                    <div className="w-[180px] flex items-center gap-1.5 overflow-hidden">
                        {node.directFiles > 0 ? (
                            <span className="text-[13px] text-gray-400 font-mono truncate" title={node.latestFile}>
                                {node.latestFile || '\u2014'}
                            </span>
                        ) : (
                            <span className="text-xs text-gray-600">&mdash;</span>
                        )}
                    </div>

                    {/* Actions — always visible, only for baselined dirs */}
                    <div className="w-[120px] flex items-center justify-end gap-1.5">
                        {node.directFiles > 0 && (
                            <>
                                <button
                                    onClick={(e) => { e.stopPropagation(); setSuspendTarget(node.files[0].id); }}
                                    className="px-2 py-1 rounded-lg text-[11px] font-semibold bg-amber-500/[0.08] hover:bg-amber-500/20 text-amber-400/70 hover:text-amber-300 border border-amber-500/15 hover:border-amber-500/40 transition-all flex items-center gap-1"
                                    title="Suspend"
                                >
                                    <Clock className="w-3 h-3" />
                                    Suspend
                                </button>
                                <button
                                    onClick={(e) => { e.stopPropagation(); setDeleteTarget(node.files[0].id); }}
                                    className="px-2 py-1 rounded-lg text-[11px] font-semibold bg-red-500/[0.06] hover:bg-red-500/15 text-red-400/60 hover:text-red-300 border border-red-500/15 hover:border-red-500/40 transition-all flex items-center gap-1"
                                    title="Remove"
                                >
                                    <Trash2 className="w-3 h-3" />
                                    Remove
                                </button>
                            </>
                        )}
                    </div>

                    {/* Agent + Allow Dir button */}
                    <div className="w-[220px] flex items-center justify-center gap-1.5 overflow-hidden">
                        {node.globAgents.size > 0 && (
                            Array.from(node.globAgents).slice(0, 2).map(a => (
                                <span key={a} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 shrink-0">
                                    <Bot className="w-3 h-3 text-cyan-400/60 shrink-0" />
                                    {aiAgentDisplayName(a)}
                                </span>
                            ))
                        )}
                        {node.globAgents.size > 2 && (
                            <span className="text-[10px] text-gray-500 shrink-0">+{node.globAgents.size - 2}</span>
                        )}
                        <button
                            onClick={(e) => { e.stopPropagation(); setAddDirTarget({ path: node.fullPath }); }}
                            className="shrink-0 inline-flex items-center justify-center w-5 h-5 rounded-full text-gray-500 border border-transparent hover:bg-green-500/10 hover:text-green-400 hover:border-green-500/20 transition-all opacity-0 group-hover:opacity-100"
                            title={node.agents.size > 0 ? `Add agent for ${node.fullPath}` : `Allow ${node.fullPath}`}
                        >
                            <Plus className="w-3 h-3" />
                        </button>
                    </div>

                    {/* Hits — direct only */}
                    <span className={`w-[60px] text-right text-sm font-bold tabular-nums ${
                        node.directFiles === 0 ? 'text-gray-600' :
                        node.directHits > 100 ? 'text-green-400' : node.directHits > 10 ? 'text-yellow-400' : 'text-gray-500'
                    }`}>
                        {node.directFiles > 0 ? node.directHits.toLocaleString() : ''}
                    </span>

                    {/* Last seen — direct files only */}
                    <div className="w-[140px] flex items-center gap-1.5 justify-end">
                        {node.directFiles > 0 && node.maxLastSeen ? (
                            <>
                                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: freshColor }} />
                                <span className="text-xs text-gray-500 tabular-nums whitespace-nowrap">{formatDate(node.maxLastSeen)}</span>
                            </>
                        ) : (
                            <span className="text-xs text-gray-600">&mdash;</span>
                        )}
                    </div>
                </div>
            </div>

            {/* Expanded content */}
            <AnimatePresence initial={false}>
                {isExpanded && hasContent && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2, ease: 'easeInOut' }}
                        className="overflow-hidden"
                    >
                        <div className="relative">
                            {/* Continuation line for nested items */}
                            {depth >= 0 && (
                                <div
                                    className="absolute top-0 bottom-0 border-l border-white/[0.06]"
                                    style={{ left: `${(depth + 1) * 24 + 11 + (depth > 0 ? 20 : 0)}px` }}
                                />
                            )}

                            {/* Sub-directory nodes */}
                            {node.children.map((child, i) => (
                                <TreeRows
                                    key={`d-${child.fullPath}-${i}`}
                                    node={child}
                                    depth={depth + 1}
                                    maxHits={maxHits}
                                    expandedDirs={expandedDirs}
                                    setExpandedDirs={setExpandedDirs}
                                    setSuspendTarget={setSuspendTarget}
                                    setDeleteTarget={setDeleteTarget}
                                    setAddDirTarget={setAddDirTarget}
                                    formatDate={formatDate}
                                    formatExpiresAt={formatExpiresAt}
                                    freshnessColor={freshnessColor}
                                    isLast={i === node.children.length - 1 && node.files.length === 0}
                                />
                            ))}

                            {/* Leaf files */}
                            {node.files.length > 0 && (
                                <div
                                    className="space-y-px py-1"
                                    style={{ marginLeft: `${(depth + 1) * 24 + (depth > 0 ? 20 : 0) + 24}px` }}
                                >
                                    {node.files.map((baseline, i) => {
                                        const fileName = baseline.pattern.split('/').pop() || baseline.pattern
                                        const fileHitPct = maxHits > 0 ? (baseline.hit_count / maxHits) * 100 : 0
                                        const fileFresh = freshnessColor(baseline.last_seen)
                                        const expiryLabel = formatExpiresAt(baseline.expires_at, baseline.suspended_until)
                                        const isExpiredFile = expiryLabel === 'Expired'
                                        return (
                                            <div
                                                key={`f-${baseline.id}-${i}`}
                                                className="group/file flex items-center gap-2.5 h-8 px-3 rounded-md hover:bg-white/[0.03] transition-all duration-150"
                                            >
                                                <FileText className="w-3.5 h-3.5 text-blue-400/30 shrink-0" />

                                                <code className="text-[13px] text-gray-400 font-mono truncate group-hover/file:text-gray-200 transition-colors" title={baseline.pattern}>
                                                    {fileName}
                                                </code>

                                                {baseline.source === 'user_confirmed' && (
                                                    <span className="shrink-0 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-green-500/10 text-green-400/80 border border-green-500/15">
                                                        <UserCheck className="w-2.5 h-2.5" />
                                                    </span>
                                                )}

                                                {expiryLabel && (
                                                    <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                                                        isExpiredFile ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                                    }`}>{expiryLabel}</span>
                                                )}

                                                <div className="flex-1 min-w-8" />

                                                {/* Right columns — matching directory row layout */}
                                                <div className="shrink-0 flex items-center gap-6">
                                                    {/* File actions — always visible */}
                                                    <div className="w-[180px]" />
                                                    <div className="w-[120px] flex items-center justify-end gap-1.5">
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); setSuspendTarget(baseline.id); }}
                                                            className="px-1.5 py-1 rounded-lg text-[11px] font-semibold bg-amber-500/[0.08] hover:bg-amber-500/20 text-amber-400/70 hover:text-amber-300 border border-amber-500/15 hover:border-amber-500/40 transition-all"
                                                            title="Suspend"
                                                        >
                                                            <Clock className="w-3 h-3" />
                                                        </button>
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); setDeleteTarget(baseline.id); }}
                                                            className="px-1.5 py-1 rounded-lg text-[11px] font-semibold bg-red-500/[0.06] hover:bg-red-500/15 text-red-400/60 hover:text-red-300 border border-red-500/15 hover:border-red-500/40 transition-all"
                                                            title="Remove"
                                                        >
                                                            <Trash2 className="w-3 h-3" />
                                                        </button>
                                                    </div>

                                                    {/* Agent */}
                                                    <div className="w-[220px] flex items-center justify-center overflow-hidden">
                                                        {baseline.ai_type ? (
                                                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-300/80 border border-cyan-500/15">
                                                                <Bot className="w-3 h-3 text-cyan-400/40 shrink-0" />
                                                                {aiAgentDisplayName(baseline.ai_type)}
                                                            </span>
                                                        ) : (
                                                            <span className="text-xs text-gray-600 italic">Any</span>
                                                        )}
                                                    </div>

                                                    {/* Hits */}
                                                    <span className={`w-[60px] text-right text-xs tabular-nums ${baseline.hit_count > 100 ? 'text-green-400/70' : baseline.hit_count > 10 ? 'text-yellow-400/70' : 'text-gray-600'}`}>
                                                        {baseline.hit_count}
                                                    </span>

                                                    {/* Last seen */}
                                                    <div className="w-[140px] flex items-center gap-1.5 justify-end">
                                                        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: fileFresh }} />
                                                        <span className="text-xs text-gray-600 tabular-nums whitespace-nowrap">{formatDate(baseline.last_seen)}</span>
                                                    </div>
                                                </div>
                                            </div>
                                        )
                                    })}
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}

interface NetworkPortGroupRowProps {
    group: NetworkPortGroup
    maxHits: number
    expandedDirs: Set<string>
    setExpandedDirs: React.Dispatch<React.SetStateAction<Set<string>>>
    setSuspendTarget: (id: number) => void
    setDeleteTarget: (id: number | null) => void
    formatDate: (dateStr: string) => string
    formatExpiresAt: (expiresAt?: string, suspendedUntil?: string) => string | null
    freshnessColor: (dateStr: string) => string
    domainMap: Record<string, IPEnrichment>
    domainLoading: Record<string, boolean>
    onResolveDomain: (cidr: string) => void
}

function NetworkPortGroupRow({ group, maxHits, expandedDirs, setExpandedDirs, setSuspendTarget, setDeleteTarget, formatDate, formatExpiresAt, freshnessColor, domainMap, domainLoading, onResolveDomain }: NetworkPortGroupRowProps) {
    const key = `net:port:${group.port}`
    const isExpanded = expandedDirs.has(key)
    const isSingle = group.subnets.length === 1
    const freshColor = group.maxLastSeen ? freshnessColor(group.maxLastSeen) : '#64748b'
    const portDisplay = group.port === 0 ? ':*' : `:${group.port}`
    const topSubnet = group.subnets[0] // highest-hit subnet for the mini bar

    const toggle = () => {
        if (isSingle) return
        setExpandedDirs(prev => {
            const next = new Set(prev)
            if (next.has(key)) next.delete(key)
            else next.add(key)
            return next
        })
    }

    return (
        <div className="relative">
            {/* Port group header */}
            <div
                className={`group flex items-center gap-3 h-11 px-4 mx-1.5 my-0.5 rounded-xl transition-all duration-200 ${
                    isSingle ? 'hover:bg-white/[0.04] border border-transparent cursor-default' :
                    isExpanded
                        ? 'bg-gradient-to-r from-orange-500/[0.08] to-transparent border border-orange-500/20 cursor-pointer'
                        : 'hover:bg-white/[0.04] border border-transparent cursor-pointer'
                }`}
                onClick={toggle}
            >
                {/* Chevron */}
                {!isSingle ? (
                    <motion.div
                        animate={{ rotate: isExpanded ? 90 : 0 }}
                        transition={{ duration: 0.15, ease: 'easeOut' }}
                        className={`shrink-0 ${isExpanded ? 'text-orange-400' : 'text-gray-600 group-hover:text-gray-400'}`}
                    >
                        <ChevronRight className="w-4 h-4" />
                    </motion.div>
                ) : (
                    <div className="w-4 shrink-0" />
                )}

                {/* Port badge */}
                <div className={`shrink-0 flex items-center gap-1.5 px-2.5 py-1 rounded-lg ${
                    isExpanded ? 'bg-orange-500/20 border border-orange-500/30' : 'bg-white/[0.05] border border-white/[0.08]'
                } transition-colors`}>
                    <Wifi className={`w-3.5 h-3.5 ${isExpanded ? 'text-orange-400' : 'text-orange-400/60'}`} />
                    <code className={`font-mono text-[13px] font-bold ${isExpanded ? 'text-orange-300' : 'text-gray-200'}`}>
                        {portDisplay}
                    </code>
                    {group.portLabel && (
                        <span className={`text-[10px] font-semibold uppercase tracking-wider ${isExpanded ? 'text-orange-400/60' : 'text-gray-600'}`}>{group.portLabel}</span>
                    )}
                </div>

                {/* Subnet count */}
                <span className="text-[12px] text-gray-500 tabular-nums">
                    {group.subnets.length} {group.subnets.length === 1 ? 'subnet' : 'subnets'}
                </span>

                {/* Single subnet inline CIDR + domain */}
                {isSingle && (() => {
                    const cidr = group.subnets[0].cidr
                    const enrichment = domainMap[cidr]
                    const isLoading = domainLoading[cidr]
                    const displayDomain = enrichment?.domain || ''
                    const asnName = enrichment?.asn_name || ''
                    return (
                        <>
                            <code className="text-[12px] text-gray-500/80 font-mono">{cidr}</code>
                            {displayDomain ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[11px] font-medium bg-cyan-500/8 text-cyan-300/90 border border-cyan-500/15" title={`${displayDomain}${asnName ? ` (${asnName})` : ''}`}>
                                    <Globe className="w-3 h-3 text-cyan-400/50" />
                                    {displayDomain}
                                </span>
                            ) : asnName ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[11px] text-gray-500 bg-white/[0.03] border border-white/[0.06]" title={asnName}>
                                    {asnName.length > 30 ? asnName.slice(0, 28) + '...' : asnName}
                                </span>
                            ) : (
                                <button
                                    onClick={(e) => { e.stopPropagation(); onResolveDomain(cidr); }}
                                    disabled={isLoading}
                                    className="text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 hover:border-cyan-500/35 px-2 py-0.5 rounded-lg transition-all duration-200 disabled:opacity-50 text-[11px] font-medium"
                                >
                                    {isLoading ? 'Resolving...' : 'Find Domain'}
                                </button>
                            )}
                        </>
                    )
                })()}

                {/* Mini hit distribution bar (multi-subnet only) */}
                {!isSingle && group.totalHits > 0 && (
                    <div className="flex items-center gap-2 ml-1">
                        <div className="w-20 h-1.5 bg-white/[0.04] rounded-full overflow-hidden flex">
                            {group.subnets.slice(0, 5).map((s, i) => {
                                const pct = (s.baseline.hit_count / group.totalHits) * 100
                                return (
                                    <div
                                        key={i}
                                        className="h-full first:rounded-l-full last:rounded-r-full"
                                        style={{
                                            width: `${Math.max(pct, 2)}%`,
                                            background: `hsl(${25 + i * 8}, ${70 - i * 8}%, ${55 + i * 5}%)`,
                                            opacity: 1 - i * 0.12,
                                        }}
                                    />
                                )
                            })}
                        </div>
                    </div>
                )}

                <div className="flex-1 min-w-4" />

                {/* Right columns */}
                <div className="shrink-0 flex items-center gap-6">
                    {/* Agent */}
                    <div className="w-[240px] flex items-center justify-center gap-1.5 flex-wrap overflow-hidden">
                        {group.agents.size > 0 ? (
                            Array.from(group.agents).map(a => (
                                <span key={a} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                                    <Bot className="w-3 h-3 text-cyan-400/60 shrink-0" />
                                    {aiAgentDisplayName(a)}
                                </span>
                            ))
                        ) : (
                            <span className="text-xs text-gray-600 italic">Any</span>
                        )}
                    </div>

                    {/* Hits with bar */}
                    <div className="w-[90px] flex flex-col items-end gap-0.5">
                        <span className={`text-sm font-bold tabular-nums ${group.totalHits > 100 ? 'text-green-400' : group.totalHits > 10 ? 'text-yellow-400' : 'text-gray-500'}`}>
                            {group.totalHits.toLocaleString()}
                        </span>
                        <div className="w-full h-[2px] bg-white/[0.04] rounded-full overflow-hidden">
                            <div
                                className="h-full rounded-full transition-all duration-700"
                                style={{
                                    width: `${maxHits > 0 ? Math.max((group.totalHits / maxHits) * 100, 3) : 0}%`,
                                    background: group.totalHits > 100 ? '#22c55e' : group.totalHits > 10 ? '#eab308' : '#475569',
                                }}
                            />
                        </div>
                    </div>

                    {/* Last seen */}
                    <div className="w-[150px] flex items-center gap-1.5 justify-end">
                        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: freshColor }} />
                        <span className="text-[12px] text-gray-400 tabular-nums whitespace-nowrap">{group.maxLastSeen ? formatDate(group.maxLastSeen) : ''}</span>
                    </div>

                    {/* Single-subnet actions */}
                    {isSingle ? (
                        <div className="w-[80px] flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button
                                onClick={(e) => { e.stopPropagation(); setSuspendTarget(group.subnets[0].baseline.id); }}
                                className="p-1.5 rounded-lg hover:bg-amber-500/15 text-gray-600 hover:text-amber-400 transition-all"
                                title="Suspend"
                            >
                                <Clock className="w-3.5 h-3.5" />
                            </button>
                            <button
                                onClick={(e) => { e.stopPropagation(); setDeleteTarget(group.subnets[0].baseline.id); }}
                                className="p-1.5 rounded-lg hover:bg-red-500/15 text-gray-600 hover:text-red-400 transition-all"
                                title="Remove"
                            >
                                <Trash2 className="w-3.5 h-3.5" />
                            </button>
                        </div>
                    ) : (
                        <div className="w-[80px]" />
                    )}
                </div>
            </div>

            {/* Expanded subnet rows */}
            {!isSingle && (
                <AnimatePresence initial={false}>
                    {isExpanded && (
                        <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
                            className="overflow-hidden"
                        >
                            <div className="mx-1.5 ml-[52px] py-1.5 border-l border-orange-500/10 pl-3">
                                {group.subnets.map((entry, i) => {
                                    const subFresh = freshnessColor(entry.baseline.last_seen)
                                    const aiLabel = entry.baseline.ai_type ? aiAgentDisplayName(entry.baseline.ai_type) : null
                                    const expiryLabel = formatExpiresAt(entry.baseline.expires_at, entry.baseline.suspended_until)
                                    const isExpired = expiryLabel === 'Expired'
                                    const subHitPct = group.totalHits > 0 ? (entry.baseline.hit_count / group.totalHits) * 100 : 0
                                    return (
                                        <motion.div
                                            key={`net-${entry.baseline.id}-${i}`}
                                            initial={{ opacity: 0, x: -8 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: i * 0.03, duration: 0.2 }}
                                            className="group/sub flex items-center gap-3 h-9 px-3 rounded-lg hover:bg-white/[0.04] transition-all duration-150 relative"
                                        >
                                            {/* Connection dot on the border line */}
                                            <div className="absolute -left-[15px] top-1/2 -translate-y-1/2 w-[10px] border-t border-orange-500/10" />
                                            <div className="absolute -left-[15px] top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-orange-500/20 border border-orange-500/30" />

                                            {/* CIDR address */}
                                            <Globe className="w-3.5 h-3.5 text-orange-400/30 shrink-0" />
                                            <code className="text-[13px] text-gray-400 font-mono truncate group-hover/sub:text-gray-200 transition-colors min-w-0" title={entry.baseline.pattern}>
                                                {entry.cidr}
                                            </code>

                                            {/* Domain / ASN enrichment */}
                                            {(() => {
                                                const enrichment = domainMap[entry.cidr]
                                                const isLoading = domainLoading[entry.cidr]
                                                const displayDomain = enrichment?.domain || ''
                                                const asnName = enrichment?.asn_name || ''
                                                return (
                                                    <>
                                                        {displayDomain ? (
                                                            <span className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[11px] font-medium bg-cyan-500/8 text-cyan-300/90 border border-cyan-500/15" title={`${displayDomain}${asnName ? ` (${asnName})` : ''}`}>
                                                                <Globe className="w-3 h-3 text-cyan-400/50" />
                                                                {displayDomain}
                                                            </span>
                                                        ) : asnName ? (
                                                            <span className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-lg text-[11px] text-gray-500 bg-white/[0.03] border border-white/[0.06]" title={asnName}>
                                                                {asnName.length > 30 ? asnName.slice(0, 28) + '...' : asnName}
                                                            </span>
                                                        ) : (
                                                            <button
                                                                onClick={(e) => { e.stopPropagation(); onResolveDomain(entry.cidr); }}
                                                                disabled={isLoading}
                                                                className="shrink-0 text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 hover:bg-cyan-500/20 hover:border-cyan-500/35 px-2 py-0.5 rounded-lg transition-all duration-200 disabled:opacity-50 text-[11px] font-medium"
                                                            >
                                                                {isLoading ? 'Resolving...' : 'Find Domain'}
                                                            </button>
                                                        )}
                                                    </>
                                                )
                                            })()}

                                            {entry.baseline.source === 'user_confirmed' && (
                                                <span className="shrink-0 inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-green-500/10 text-green-400/80 border border-green-500/15">
                                                    <UserCheck className="w-2.5 h-2.5" />
                                                </span>
                                            )}

                                            {/* Hit share bar (inline, subtle) */}
                                            <div className="shrink-0 w-12 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                                                <div
                                                    className="h-full rounded-full"
                                                    style={{
                                                        width: `${Math.max(subHitPct, 4)}%`,
                                                        background: `hsl(25, 70%, 55%)`,
                                                        opacity: 0.7,
                                                    }}
                                                />
                                            </div>

                                            {expiryLabel && (
                                                <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                                                    isExpired ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                                }`}>{expiryLabel}</span>
                                            )}

                                            <div className="flex-1 min-w-4" />

                                            {/* Right columns */}
                                            <div className="shrink-0 flex items-center gap-6">
                                                {/* Agent */}
                                                <div className="w-[240px] flex items-center justify-center overflow-hidden">
                                                    {entry.baseline.ai_type ? (
                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-cyan-500/10 text-cyan-300/80 border border-cyan-500/15">
                                                            <Bot className="w-3 h-3 text-cyan-400/40 shrink-0" />
                                                            {aiAgentDisplayName(entry.baseline.ai_type)}
                                                        </span>
                                                    ) : (
                                                        <span className="text-xs text-gray-600 italic">Any</span>
                                                    )}
                                                </div>

                                                {/* Hits */}
                                                <div className="w-[90px] flex items-center justify-end">
                                                    <span className={`text-[12px] tabular-nums ${entry.baseline.hit_count > 100 ? 'text-green-400/70' : entry.baseline.hit_count > 10 ? 'text-yellow-400/70' : 'text-gray-600'}`}>
                                                        {entry.baseline.hit_count.toLocaleString()}
                                                    </span>
                                                </div>

                                                {/* Last seen */}
                                                <div className="w-[150px] flex items-center gap-1.5 justify-end">
                                                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: subFresh }} />
                                                    <span className="text-[11px] text-gray-500 tabular-nums whitespace-nowrap">{formatDate(entry.baseline.last_seen)}</span>
                                                </div>

                                                {/* Actions on hover */}
                                                <div className="w-[80px] flex items-center justify-end gap-1 opacity-0 group-hover/sub:opacity-100 transition-opacity">
                                                    <button
                                                        onClick={(e) => { e.stopPropagation(); setSuspendTarget(entry.baseline.id); }}
                                                        className="p-1.5 rounded-lg hover:bg-amber-500/15 text-gray-600 hover:text-amber-400 transition-all"
                                                        title="Suspend"
                                                    >
                                                        <Clock className="w-3.5 h-3.5" />
                                                    </button>
                                                    <button
                                                        onClick={(e) => { e.stopPropagation(); setDeleteTarget(entry.baseline.id); }}
                                                        className="p-1.5 rounded-lg hover:bg-red-500/15 text-gray-600 hover:text-red-400 transition-all"
                                                        title="Remove"
                                                    >
                                                        <Trash2 className="w-3.5 h-3.5" />
                                                    </button>
                                                </div>
                                            </div>
                                        </motion.div>
                                    )
                                })}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            )}
        </div>
    )
}

export default function BaselinesPage() {
    return (
        <Suspense fallback={<div className="flex items-center justify-center h-64"><Loader2 className="w-6 h-6 animate-spin text-gray-500" /></div>}>
            <Baselines />
        </Suspense>
    )
}

function Baselines() {
    const searchParams = useSearchParams();
    const [activeTab, setActiveTab] = useState<'learned' | 'allowlist' | 'exclusions' | 'never-baseline' | 'block-rules' | 'auto-suppressed'>('learned');
    const [showManualOnly, setShowManualOnly] = useState(false);
    const [baselines, setBaselines] = useState<Baseline[]>([]);
    const [summary, setSummary] = useState<BaselineSummary | null>(null);
    const [hasMore, setHasMore] = useState(false);
    const [loadingMore, setLoadingMore] = useState(false);
    const [safeDomains, setSafeDomains] = useState<SafeDomain[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<string>('');
    const [agentFilter, setAgentFilter] = useState<string>('');
    const [agentDropdownOpen, setAgentDropdownOpen] = useState(false);
    const [deleteTarget, setDeleteTarget] = useState<number | null>(null);
    const [suspendTarget, setSuspendTarget] = useState<number | null>(null);
    const [suspendDuration, setSuspendDuration] = useState<string>('7d');
    const [newDomain, setNewDomain] = useState('');
    const [newDomainDesc, setNewDomainDesc] = useState('');
    const [addingDomain, setAddingDomain] = useState(false);
    const [deleteDomainTarget, setDeleteDomainTarget] = useState<string | null>(null);
    const [patternSearch, setPatternSearch] = useState('');
    const [exclusions, setExclusions] = useState<BaselineExclusion[]>([]);
    const [deleteExclusionTarget, setDeleteExclusionTarget] = useState<number | null>(null);
    const [confirmTarget, setConfirmTarget] = useState<number | null>(null);
    const [showAddForm, setShowAddForm] = useState(false);
    const [addPattern, setAddPattern] = useState('');
    const [addSignalType, setAddSignalType] = useState<string>('file_pattern');
    const [addAiType, setAddAiType] = useState<string>('');
    const [addingBaseline, setAddingBaseline] = useState(false);
    const [addDirTarget, setAddDirTarget] = useState<{ path: string } | null>(null);
    const [addDirAiType, setAddDirAiType] = useState<string>('claude');
    const [addingDir, setAddingDir] = useState(false);
    const [toastError, setToastError] = useState<string | null>(null);
    const [toastSuccess, setToastSuccess] = useState<string | null>(null);
    const [refreshing, setRefreshing] = useState(false);
    const [expandedDirs, setExpandedDirs] = useState<Set<string>>(new Set());
    const [domainMap, setDomainMap] = useState<Record<string, IPEnrichment>>({});
    const [domainLoading, setDomainLoading] = useState<Record<string, boolean>>({});
    // Never-baseline tab state
    const [neverBaselines, setNeverBaselines] = useState<NeverBaselineEntry[]>([]);
    const [neverBaselineLoading, setNeverBaselineLoading] = useState(false);
    const [nbSystemExpanded, setNbSystemExpanded] = useState(false);
    const [nbAddSignalType, setNbAddSignalType] = useState<string>('file_pattern');
    const [nbAddPattern, setNbAddPattern] = useState('');
    const [nbAddDescription, setNbAddDescription] = useState('');
    const [addingNeverBaseline, setAddingNeverBaseline] = useState(false);
    const [deleteNeverBaselineTarget, setDeleteNeverBaselineTarget] = useState<number | null>(null);
    const [nbConflictDialog, setNbConflictDialog] = useState<{ baseline_ids: number[]; message: string } | null>(null);
    const [nbConflictPending, setNbConflictPending] = useState<{ signal_type: string; pattern: string; description: string } | null>(null);
    const [nbIsUserDefinedBlock, setNbIsUserDefinedBlock] = useState<string | null>(null);
    // Block rules tab state
    const [blockRules, setBlockRules] = useState<BlockRule[]>([])
    const [blockRulesLoading, setBlockRulesLoading] = useState(false)
    const [brAddSignalType, setBrAddSignalType] = useState('process_exec')
    const [brAddPattern, setBrAddPattern] = useState('')
    const [brAddDescription, setBrAddDescription] = useState('')
    const [brAddKillTree, setBrAddKillTree] = useState(false)
    const [addingBlockRule, setAddingBlockRule] = useState(false)
    const [deleteBlockRuleTarget, setDeleteBlockRuleTarget] = useState<number | null>(null)
    // Auto-suppressed tab state
    const [suppressedGroups, setSuppressedGroups] = useState<SuppressedGroup[]>([]);
    const [suppressedLoading, setSuppressedLoading] = useState(false);
    const [suppressedSubTab, setSuppressedSubTab] = useState<'baselines' | 'command-noise'>('baselines');
    const [noiseFilters, setNoiseFilters] = useState<NoiseFilters | null>(null);
    const [noiseLoading, setNoiseLoading] = useState(false);

    const sentinelRef = useRef<HTMLDivElement>(null);

    // Handle ?tab=files query param from findings/incidents "Allow Directory" link
    useEffect(() => {
        const tab = searchParams.get('tab');
        if (tab === 'files') {
            setActiveTab('learned');
            setFilter('file_pattern');
        }
    }, [searchParams]);

    useEffect(() => {
        if (activeTab === 'learned') {
            fetchLearnedData(true);
        } else if (activeTab === 'allowlist') {
            fetchSafeDomains();
        } else if (activeTab === 'exclusions') {
            fetchExclusions();
        } else if (activeTab === 'never-baseline') {
            fetchNeverBaselines();
        } else if (activeTab === 'block-rules') {
            fetchBlockRules();
        } else if (activeTab === 'auto-suppressed') {
            fetchSuppressedSummary();
            fetchNoiseFilters();
        }
    }, [activeTab]);

    async function fetchLearnedData(reset: boolean) {
        try {
            if (reset) {
                // If we already have data, show a subtle refreshing indicator instead of clearing
                if (baselines.length > 0) {
                    setRefreshing(true);
                } else {
                    setLoading(true);
                }
                setHasMore(false);
            } else {
                setLoadingMore(true);
            }
            const offset = reset ? 0 : baselines.length;
            const [result, summaryData] = await Promise.all([
                getBaselines({ limit: PAGE_SIZE, offset }).catch(() => ({ baselines: [] as Baseline[], has_more: false })),
                reset ? getBaselineSummary().catch(() => null) : Promise.resolve(null),
            ]);
            if (reset) {
                setBaselines(result.baselines);
                if (summaryData) setSummary(summaryData);
            } else {
                setBaselines(prev => [...prev, ...result.baselines]);
            }
            setHasMore(result.has_more);
        } catch (err) {
            console.error('Failed to fetch baselines:', err);
        } finally {
            setLoading(false);
            setLoadingMore(false);
            setRefreshing(false);
        }
    }

    // Infinite scroll: observe sentinel element
    const observerCallback = useCallback((entries: IntersectionObserverEntry[]) => {
        if (entries[0]?.isIntersecting && hasMore && !loadingMore && !loading) {
            fetchLearnedData(false);
        }
    }, [hasMore, loadingMore, loading, baselines.length]);

    useEffect(() => {
        const sentinel = sentinelRef.current;
        if (!sentinel) return;
        const observer = new IntersectionObserver(observerCallback, { rootMargin: '200px' });
        observer.observe(sentinel);
        return () => observer.disconnect();
    }, [observerCallback]);

    async function handleDeleteBaseline(id: number) {
        try {
            await deleteBaseline(id);
            setBaselines(baselines.filter(b => b.id !== id));
        } catch (err) {
            console.error('Failed to delete baseline:', err);
        }
    }

    async function handleSuspendBaseline(id: number, expiresIn: string) {
        try {
            const result = await suspendBaseline(id, expiresIn);
            setBaselines(baselines.map(b => b.id === id ? { ...b, suspended_until: result.suspended_until } : b));
        } catch (err) {
            console.error('Failed to suspend baseline:', err);
        }
    }

    /** Extract a representative IP from a CIDR like "3.89.172.0/24" → "3.89.172.1" */
    function cidrToIP(cidr: string): string {
        const slash = cidr.indexOf('/')
        if (slash === -1) return cidr // bare IP
        const base = cidr.substring(0, slash)
        if (base.endsWith('.0')) return base.slice(0, -1) + '1'
        return base
    }

    async function handleResolveDomain(cidr: string) {
        if (domainLoading[cidr]) return
        // Allow retry if previous result had no domain
        const existing = domainMap[cidr]
        if (existing?.domain) return
        setDomainLoading(prev => ({ ...prev, [cidr]: true }))
        try {
            const ip = cidrToIP(cidr)
            const result = await resolveIP(ip)
            setDomainMap(prev => ({ ...prev, [cidr]: result }))
        } catch (err) {
            console.error('Domain resolution failed for', cidr, err)
        } finally {
            setDomainLoading(prev => ({ ...prev, [cidr]: false }))
        }
    }

    function showError(err: unknown) {
        let msg = 'Something went wrong';
        if (err instanceof ApiError) {
            try { msg = JSON.parse(err.body).error || err.body; } catch { msg = err.body; }
        } else if (err instanceof Error) {
            msg = err.message;
        }
        setToastError(msg);
        setTimeout(() => setToastError(null), 5000);
    }

    function showSuccess(msg: string) {
        setToastSuccess(msg);
        setTimeout(() => setToastSuccess(null), 6000);
    }

    async function handleAddBaseline() {
        if (!addPattern.trim()) return;
        try {
            setAddingBaseline(true);
            await createBaseline({ signal_type: addSignalType, pattern: addPattern.trim(), ...(addAiType ? { ai_type: addAiType } : {}) });
            setAddPattern('');
            setAddAiType('');
            setShowAddForm(false);
            showSuccess('Baseline created — refreshing list...');
            fetchLearnedData(true);
        } catch (err: unknown) {
            if (err instanceof ApiError && err.status === 400) {
                try {
                    const body = JSON.parse(err.body);
                    if (body.is_user_defined) {
                        setNbIsUserDefinedBlock(body.error || 'This pattern is on your Never-Baseline list. Remove it there first.');
                        return;
                    }
                } catch { /* fall through */ }
            }
            showError(err);
        } finally {
            setAddingBaseline(false);
        }
    }

    async function handleAddDirBaseline() {
        if (!addDirTarget) return;
        try {
            setAddingDir(true);
            const dirPath = addDirTarget.path;
            const result = await createBaseline({ signal_type: 'file_pattern', pattern: dirPath + '/**', ai_type: addDirAiType });
            setAddDirTarget(null);
            let msg = `Directory ${dirPath} baselined`;
            if (result.retroactive_resolved && result.retroactive_resolved > 0) msg += ` — ${result.retroactive_resolved} findings auto-resolved`;
            showSuccess(msg + '. Findings will be auto-resolved in the background — may take up to 30 seconds to fully reflect.');
            // Optimistic child removal: immediately filter out child baselines
            // covered by the new directory glob to prevent tree flicker.
            const dirPrefix = dirPath + '/';
            const newGlob = dirPath + '/**';
            setBaselines(prev => prev.filter(b =>
                !b.pattern.startsWith(dirPrefix) || b.pattern === newGlob
            ));
            // Then refetch for the authoritative state from the backend.
            fetchLearnedData(true);
        } catch (err: unknown) {
            if (err instanceof ApiError && err.status === 400) {
                try {
                    const body = JSON.parse(err.body);
                    if (body.is_user_defined) {
                        setAddDirTarget(null);
                        setNbIsUserDefinedBlock(body.error || 'This directory is on your Never-Baseline list. Remove it there first.');
                        return;
                    }
                } catch { /* fall through */ }
            }
            showError(err);
        } finally {
            setAddingDir(false);
        }
    }


    async function handleConfirmBaseline(id: number) {
        try {
            await confirmBaseline(id);
            setBaselines(baselines.map(b => b.id === id ? { ...b, source: 'user_confirmed', expires_at: undefined } : b));
        } catch (err) {
            console.error('Failed to confirm baseline:', err);
        }
    }

    async function fetchSafeDomains() {
        try {
            setLoading(true);
            const data = await getSafeDomains().catch(() => []);
            setSafeDomains(data);
        } catch (err) {
            console.error('Failed to fetch safe domains:', err);
        } finally {
            setLoading(false);
        }
    }

    async function handleAddDomain() {
        const domain = newDomain.trim();
        if (!domain) return;
        try {
            setAddingDomain(true);
            const added = await addSafeDomain(domain, newDomainDesc.trim());
            setSafeDomains(prev => [...prev, added].sort((a, b) => a.domain.localeCompare(b.domain)));
            setNewDomain('');
            setNewDomainDesc('');
        } catch (err) {
            console.error('Failed to add safe domain:', err);
        } finally {
            setAddingDomain(false);
        }
    }

    async function handleDeleteDomain(id: string) {
        try {
            await deleteSafeDomain(id);
            setSafeDomains(prev => prev.filter(d => d.id !== id));
        } catch (err) {
            console.error('Failed to delete safe domain:', err);
        }
    }

    async function fetchExclusions() {
        try {
            setLoading(true);
            const data = await getBaselineExclusions().catch(() => []);
            setExclusions(data);
        } catch (err) {
            console.error('Failed to fetch exclusions:', err);
        } finally {
            setLoading(false);
        }
    }

    async function handleDeleteExclusion(id: number) {
        try {
            await deleteBaselineExclusion(id);
            setExclusions(prev => prev.filter(e => e.id !== id));
        } catch (err) {
            console.error('Failed to delete exclusion:', err);
        }
    }

    async function fetchNeverBaselines() {
        try {
            setNeverBaselineLoading(true);
            const data = await getNeverBaselines().catch(() => []);
            setNeverBaselines(data);
        } catch (err) {
            console.error('Failed to fetch never-baselines:', err);
        } finally {
            setNeverBaselineLoading(false);
        }
    }

    async function handleAddNeverBaseline() {
        if (!nbAddPattern.trim()) return;
        const params = { signal_type: nbAddSignalType, pattern: nbAddPattern.trim(), description: nbAddDescription.trim() };
        try {
            setAddingNeverBaseline(true);
            const entry = await createNeverBaseline(params);
            setNeverBaselines(prev => [...prev, entry]);
            setNbAddPattern('');
            setNbAddDescription('');
            showSuccess('Never-baseline rule added');
        } catch (err: unknown) {
            if (err instanceof ApiError) {
                if (err.status === 409) {
                    try {
                        const body = JSON.parse(err.body);
                        setNbConflictPending(params);
                        setNbConflictDialog({ baseline_ids: body.baseline_ids || [], message: body.message || '' });
                        return;
                    } catch { /* fall through */ }
                }
                showError(err);
            } else {
                showError(err);
            }
        } finally {
            setAddingNeverBaseline(false);
        }
    }

    async function handleNeverBaselineConflictConfirm() {
        if (!nbConflictPending) return;
        // Delete the conflicting baselines then retry
        if (nbConflictDialog) {
            for (const id of nbConflictDialog.baseline_ids) {
                try { await deleteBaseline(id); } catch { /* ignore */ }
            }
            setBaselines(prev => prev.filter(b => !nbConflictDialog.baseline_ids.includes(b.id)));
        }
        setNbConflictDialog(null);
        try {
            const entry = await createNeverBaseline(nbConflictPending);
            setNeverBaselines(prev => [...prev, entry]);
            setNbAddPattern('');
            setNbAddDescription('');
            showSuccess('Never-baseline rule added (conflicting baselines removed)');
        } catch (err) {
            showError(err);
        } finally {
            setNbConflictPending(null);
        }
    }

    async function handleDeleteNeverBaseline(id: number) {
        try {
            await deleteNeverBaseline(id);
            setNeverBaselines(prev => prev.filter(e => e.id !== id));
            showSuccess('Never-baseline rule removed');
        } catch (err) {
            showError(err);
        }
    }

    async function fetchBlockRules() {
        try {
            setBlockRulesLoading(true)
            const rules = await getBlockRules()
            setBlockRules(rules || [])
        } catch (err) {
            console.error('Failed to fetch block rules:', err)
        } finally {
            setBlockRulesLoading(false)
        }
    }

    async function fetchSuppressedSummary() {
        try {
            setSuppressedLoading(true);
            const groups = await getSuppressedSummary();
            setSuppressedGroups(groups || []);
        } catch (err) {
            console.error('Failed to fetch suppressed summary:', err);
        } finally {
            setSuppressedLoading(false);
        }
    }

    async function fetchNoiseFilters() {
        try {
            setNoiseLoading(true);
            const filters = await getNoiseFilters();
            setNoiseFilters(filters);
        } catch (err) {
            console.error('Failed to fetch noise filters:', err);
        } finally {
            setNoiseLoading(false);
        }
    }

    async function handleAddBlockRule() {
        if (!brAddPattern.trim()) return
        try {
            setAddingBlockRule(true)
            const rule = await createBlockRule({ signal_type: brAddSignalType, pattern: brAddPattern.trim(), description: brAddDescription.trim(), kill_tree: brAddKillTree })
            setBlockRules(prev => [...prev, rule])
            setBrAddPattern('')
            setBrAddDescription('')
            setBrAddKillTree(false)
            showSuccess('Block rule added')
        } catch (err) {
            showError(err)
        } finally {
            setAddingBlockRule(false)
        }
    }

    async function handleToggleBlockRule(id: number, enabled: boolean) {
        try {
            await updateBlockRule(id, { enabled })
            setBlockRules(prev => prev.map(r => r.id === id ? { ...r, enabled } : r))
        } catch (err) {
            showError(err)
        }
    }

    async function handleDeleteBlockRule(id: number) {
        try {
            await deleteBlockRule(id)
            setBlockRules(prev => prev.filter(r => r.id !== id))
            showSuccess('Block rule removed')
        } catch (err) {
            showError(err)
        }
    }

    // Label for either timer on a baseline: a user pause (suspended_until) or a
    // temporary allow (expires_at). Pass the baseline's own fields.
    function formatExpiresAt(expiresAt?: string, suspendedUntil?: string): string | null {
        const now = new Date();
        if (suspendedUntil) {
            const until = new Date(suspendedUntil);
            const diff = until.getTime() - now.getTime();
            if (diff > 0) {
                const days = Math.ceil(diff / 86400000);
                if (days <= 1) return 'Suspended until tomorrow';
                if (days < 7) return `Suspended for ${days}d`;
                return `Suspended until ${until.toLocaleDateString()}`;
            }
        }
        if (!expiresAt) return null;
        const exp = new Date(expiresAt);
        const diff = exp.getTime() - now.getTime();
        if (diff <= 0) return 'Expired';
        const days = Math.ceil(diff / 86400000);
        if (days <= 1) return 'Expires today';
        if (days < 7) return `Expires in ${days}d`;
        if (days < 30) return `Expires in ${Math.floor(days / 7)}w`;
        return `Expires ${exp.toLocaleDateString()}`;
    }

    const signalTypes = ['file_pattern', 'binary', 'command', 'network_dest', 'dns_domain', 'file_activity', 'container_escape'];

    // Helper: is this baseline currently suspended?
    const isSuspended = (b: Baseline) => {
        if (!b.expires_at) return false;
        return new Date(b.expires_at).getTime() > Date.now();
    };

    // All non-suspended baselines (unified view), plus suspended for exclusions tab
    const activeBaselines = baselines.filter(b => !isSuspended(b));
    const suspendedBaselines = baselines.filter(b => isSuspended(b));
    const manualCount = activeBaselines.filter(b => b.source === 'user_confirmed').length;
    const visibleBaselines = showManualOnly ? activeBaselines.filter(b => b.source === 'user_confirmed') : activeBaselines;

    // Unique AI agent types from visible baselines
    const uniqueAgents = useMemo(() => {
        const agents = new Set<string>();
        visibleBaselines.forEach(b => {
            agents.add(b.ai_type || '');
        });
        return Array.from(agents).sort((a, b) => {
            if (!a) return 1;
            if (!b) return -1;
            return a.localeCompare(b);
        });
    }, [visibleBaselines]);

    // Apply signal type, agent, and pattern search filters
    const filteredBaselines = visibleBaselines.filter(b => {
        if (filter) {
            if (filter === 'binary') {
                if (b.signal_type !== 'binary' && b.signal_type !== 'command_binary') return false;
            } else if (b.signal_type !== filter) return false;
        }
        if (agentFilter !== '') {
            const bAgent = b.ai_type || '';
            if (agentFilter === '__unscoped__') {
                if (bAgent !== '') return false;
            } else {
                if (bAgent !== agentFilter) return false;
            }
        }
        if (patternSearch.trim()) {
            const q = patternSearch.toLowerCase();
            if (!b.pattern.toLowerCase().includes(q)) return false;
        }
        return true;
    });

    // Max hit count for heat bar scaling
    const maxHits = useMemo(() => {
        return filteredBaselines.reduce((max, b) => Math.max(max, b.hit_count), 0);
    }, [filteredBaselines]);

    // Build a single merged file tree from all file_pattern baselines (regardless of agent).
    const { fileTree, networkPortGroups, binaryRows, commandRows, dnsRows, containerRows, fileActivityRows, otherRows } = useMemo(() => {
        const fileBaselines: Baseline[] = []
        const networkBaselines: Baseline[] = []
        const binaryList: Baseline[] = []
        const commandList: Baseline[] = []
        const dnsList: Baseline[] = []
        const containerList: Baseline[] = []
        const fileActivityList: Baseline[] = []
        const otherList: Baseline[] = []

        for (const b of filteredBaselines) {
            if (b.signal_type === 'network_dest') {
                networkBaselines.push(b)
            } else if (b.signal_type === 'file_pattern' || (b.pattern.startsWith('/') && !b.pattern.includes(':') && !b.pattern.includes('&&') && !b.pattern.includes('eval '))) {
                fileBaselines.push(b)
            } else if (b.signal_type === 'binary' || b.signal_type === 'command_binary') {
                binaryList.push(b)
            } else if (b.signal_type === 'command' || b.signal_type === 'command_file') {
                commandList.push(b)
            } else if (b.signal_type === 'dns_domain') {
                dnsList.push(b)
            } else if (b.signal_type === 'container_escape') {
                containerList.push(b)
            } else if (b.signal_type === 'file_activity') {
                fileActivityList.push(b)
            } else {
                otherList.push(b)
            }
        }

        // Build network port groups
        const portMap = new Map<number, NetworkSubnetEntry[]>()
        for (const b of networkBaselines) {
            const { cidr, port } = parseCIDRPort(b.pattern)
            const entries = portMap.get(port) || []
            entries.push({ baseline: b, cidr, port })
            portMap.set(port, entries)
        }
        const netGroups: NetworkPortGroup[] = []
        for (const [port, subnets] of portMap) {
            subnets.sort((a, b) => b.baseline.hit_count - a.baseline.hit_count)
            const agents = new Set<string>()
            let totalHits = 0
            let maxLastSeen = ''
            for (const s of subnets) {
                totalHits += s.baseline.hit_count
                if (s.baseline.last_seen > maxLastSeen) maxLastSeen = s.baseline.last_seen
                if (s.baseline.ai_type) agents.add(s.baseline.ai_type)
            }
            netGroups.push({
                port,
                portLabel: wellKnownPorts[port] || '',
                subnets,
                totalHits,
                maxLastSeen,
                agents,
            })
        }
        netGroups.sort((a, b) => b.totalHits - a.totalHits)

        // Build a single unified tree from all file baselines
        const root: TreeNode = { name: '/', fullPath: '/', displayPath: '/', children: [], files: [], totalFiles: 0, totalHits: 0, directFiles: 0, directHits: 0, maxLastSeen: '', latestFile: '', agents: new Set(), globAgents: new Set(), hasConfirmed: false, dirBaselineId: null, dirBaselineAgent: '' }

        for (const b of fileBaselines) {
            // Normalize Windows backslash paths to forward-slash
            const normalizedPattern = b.pattern.replace(/\\/g, '/')
            // Directory wildcard patterns like "/home/alice/go/**" are directory-level baselines
            const isDirWildcard = normalizedPattern.endsWith('/**')
            const effectivePath = isDirWildcard ? normalizedPattern.slice(0, -3) : normalizedPattern
            const lastSlash = effectivePath.lastIndexOf('/')
            const dirPath = isDirWildcard ? effectivePath : (lastSlash > 0 ? effectivePath.substring(0, lastSlash) : '/')
            const parts = dirPath.split('/').filter(Boolean)

            // Walk/create tree path
            let node = root
            let currentPath = ''
            for (const part of parts) {
                // Handle Windows drive letter roots (e.g. "C:") — don't prepend "/"
                if (currentPath === '' && /^[A-Za-z]:$/.test(part)) {
                    currentPath = part
                } else {
                    currentPath += '/' + part
                }
                let child = node.children.find(c => c.name.toLowerCase() === part.toLowerCase())
                if (!child) {
                    child = { name: part, fullPath: currentPath, displayPath: currentPath, children: [], files: [], totalFiles: 0, totalHits: 0, directFiles: 0, directHits: 0, maxLastSeen: '', latestFile: '', agents: new Set(), globAgents: new Set(), hasConfirmed: false, dirBaselineId: null, dirBaselineAgent: '' }
                    node.children.push(child)
                }
                node = child
            }
            if (isDirWildcard) {
                // Directory wildcard: mark this directory node as baselined
                if (b.ai_type) { node.agents.add(b.ai_type); node.globAgents.add(b.ai_type) }
                // Store as a synthetic file so directFiles count and stats work
                node.files.push(b)
            } else {
                node.files.push(b)
                if (b.ai_type) node.agents.add(b.ai_type)
            }
        }

        // Aggregate stats bottom-up
        function aggregate(node: TreeNode): void {
            for (const child of node.children) aggregate(child)
            const childFiles = node.children.reduce((s, c) => s + c.totalFiles, 0)
            const childHits = node.children.reduce((s, c) => s + c.totalHits, 0)
            node.directFiles = node.files.length
            node.directHits = node.files.reduce((s, f) => s + f.hit_count, 0)
            node.totalFiles = node.directFiles + childFiles
            node.totalHits = node.directHits + childHits

            // maxLastSeen and latestFile only from direct files in this directory
            let latest = ''
            let latestName = ''
            for (const f of node.files) {
                if (f.last_seen > latest) {
                    latest = f.last_seen
                    latestName = f.pattern.endsWith('/**') ? '(entire directory)' : (f.pattern.split('/').pop() || '')
                }
            }
            node.maxLastSeen = latest
            node.latestFile = latestName

            // hasConfirmed: any direct file with source='user_confirmed'
            node.hasConfirmed = node.files.some(f => f.source === 'user_confirmed')

            // agents only from direct files — no bubbling from children
            node.children.sort((a, b) => b.totalHits - a.totalHits)
        }
        aggregate(root)

        // Collapse single-child chains: if a node has 1 child and 0 files, merge into child
        function collapse(node: TreeNode): TreeNode {
            node.children = node.children.map(collapse)
            if (node.children.length === 1 && node.files.length === 0 && node.name !== '/') {
                const child = node.children[0]
                return { ...child, name: node.name + '/' + child.name, displayPath: child.fullPath }
            }
            return node
        }
        const collapsed = collapse(root)

        // Promote root's children to top level
        const trees = collapsed.children
        // Root-level files (rare)
        for (const f of collapsed.files) otherList.push(f)
        trees.sort((a, b) => b.totalHits - a.totalHits)

        binaryList.sort((a, b) => b.hit_count - a.hit_count)
        commandList.sort((a, b) => b.hit_count - a.hit_count)
        dnsList.sort((a, b) => b.hit_count - a.hit_count)
        containerList.sort((a, b) => b.hit_count - a.hit_count)
        fileActivityList.sort((a, b) => b.hit_count - a.hit_count)
        otherList.sort((a, b) => b.hit_count - a.hit_count)
        return { fileTree: trees, networkPortGroups: netGroups, binaryRows: binaryList, commandRows: commandList, dnsRows: dnsList, containerRows: containerList, fileActivityRows: fileActivityList, otherRows: otherList }
    }, [filteredBaselines]);

    // Use server summary for accurate tile counts — sum both sources
    // command_binary is merged into binary for display purposes
    const typeCounts = signalTypes.reduce((acc, type) => {
        if (summary) {
            const auto = summary.buckets.find(b => b.source === 'auto' && b.signal_type === type)?.count ?? 0;
            const manual = summary.buckets.find(b => b.source === 'manual' && b.signal_type === type)?.count ?? 0;
            acc[type] = showManualOnly ? manual : auto + manual;
        } else {
            acc[type] = visibleBaselines.filter(b => b.signal_type === type).length;
        }
        // Merge command_binary into binary
        if (type === 'binary') {
            if (summary) {
                const cbAuto = summary.buckets.find(b => b.source === 'auto' && b.signal_type === 'command_binary')?.count ?? 0;
                const cbManual = summary.buckets.find(b => b.source === 'manual' && b.signal_type === 'command_binary')?.count ?? 0;
                acc[type] += showManualOnly ? cbManual : cbAuto + cbManual;
            } else {
                acc[type] += visibleBaselines.filter(b => b.signal_type === 'command_binary').length;
            }
        }
        return acc;
    }, {} as Record<string, number>);

    const summaryTotal = (() => {
        if (!summary) return visibleBaselines.length;
        return signalTypes.reduce((sum, type) => sum + (typeCounts[type] ?? 0), 0);
    })();
    const totalAll = (() => {
        if (!summary) return activeBaselines.length;
        // Sum all signalTypes + command_binary (merged into binary for display)
        const allTypes = [...signalTypes, 'command_binary'];
        return allTypes.reduce((sum, type) => {
            const auto = summary.buckets.find(b => b.source === 'auto' && b.signal_type === type)?.count ?? 0;
            const manual = summary.buckets.find(b => b.source === 'manual' && b.signal_type === type)?.count ?? 0;
            return sum + auto + manual;
        }, 0);
    })();

    return (
        <div className="space-y-7">
            {/* Header */}
            <PageHeading
                title="Behavioral Baselines"
                subtitle="Learned behavioral patterns from observed activity"
                actions={
                    <div className="flex items-center gap-2">
                        {/* Tab switcher */}
                        <div className="flex items-center bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl p-1">
                            <button
                                onClick={() => setActiveTab('learned')}
                                className={`px-4 py-2 text-[11px] font-semibold rounded-xl transition-all duration-200 ${activeTab === 'learned'
                                    ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                }`}
                            >
                                Learned Behavior
                            </button>
                            <button
                                onClick={() => setActiveTab('allowlist')}
                                className={`px-4 py-2 text-[11px] font-semibold rounded-xl transition-all duration-200 ${activeTab === 'allowlist'
                                    ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                }`}
                            >
                                Domain Allowlist
                            </button>
                            <button
                                onClick={() => setActiveTab('exclusions')}
                                className={`px-4 py-2 text-[11px] font-semibold rounded-xl transition-all duration-200 ${activeTab === 'exclusions'
                                    ? 'bg-white/[0.12] text-white shadow-sm border border-white/[0.08]'
                                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                }`}
                            >
                                Exclusions{(exclusions.length + suspendedBaselines.length) > 0 ? ` (${exclusions.length + suspendedBaselines.length})` : ''}
                            </button>
                            <button
                                onClick={() => setActiveTab('never-baseline')}
                                className={`px-4 py-2 text-[11px] font-semibold rounded-xl transition-all duration-200 flex items-center gap-1.5 ${activeTab === 'never-baseline'
                                    ? 'bg-red-500/[0.15] text-red-300 shadow-sm border border-red-500/[0.25]'
                                    : 'text-gray-400 hover:text-red-300 hover:bg-red-500/[0.06]'
                                }`}
                            >
                                <Ban className="w-3 h-3" />
                                Never Baseline
                                {neverBaselines.filter(e => e.source === 'user').length > 0 && (
                                    <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] bg-red-500/20 text-red-400 tabular-nums">{neverBaselines.filter(e => e.source === 'user').length}</span>
                                )}
                            </button>
                            <button
                                onClick={() => setActiveTab('block-rules')}
                                className={`px-4 py-2 text-[11px] font-semibold rounded-xl transition-all duration-200 flex items-center gap-1.5 ${activeTab === 'block-rules'
                                    ? 'bg-red-500/[0.15] text-red-300 shadow-sm border border-red-500/[0.25]'
                                    : 'text-gray-400 hover:text-red-300 hover:bg-red-500/[0.06]'
                                }`}
                            >
                                <ShieldOff className="w-3 h-3" />
                                Block Rules
                                {blockRules.filter(r => r.source === 'user').length > 0 && (
                                    <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] bg-red-500/20 text-red-400 tabular-nums">{blockRules.filter(r => r.source === 'user').length}</span>
                                )}
                            </button>
                            <button
                                onClick={() => setActiveTab('auto-suppressed')}
                                className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap flex items-center gap-1.5 ${
                                    activeTab === 'auto-suppressed'
                                        ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
                                        : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.04]'
                                }`}
                            >
                                <Eye className="w-3.5 h-3.5" />
                                Auto-Suppressed
                                {suppressedGroups.length > 0 && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-400/70">
                                        {suppressedGroups.reduce((sum, g) => sum + g.count, 0)}
                                    </span>
                                )}
                            </button>
                        </div>
                        {activeTab === 'learned' && (
                            <button
                                onClick={() => setShowAddForm(!showAddForm)}
                                className={`p-2.5 border-2 rounded-2xl transition-all duration-200 flex items-center gap-1.5 ${
                                    showAddForm
                                        ? 'bg-green-500/10 border-green-500/30 text-green-400'
                                        : 'bg-[#0d1117]/60 border-white/[0.07] text-gray-400 hover:text-green-400 hover:bg-green-500/[0.06] hover:border-green-500/20'
                                }`}
                                title="Allow Pattern"
                            >
                                <Plus className="w-4 h-4" />
                            </button>
                        )}
                        <button
                            onClick={() => activeTab === 'learned' ? fetchLearnedData(true) : activeTab === 'allowlist' ? fetchSafeDomains() : activeTab === 'block-rules' ? fetchBlockRules() : activeTab === 'auto-suppressed' ? (fetchSuppressedSummary(), fetchNoiseFilters()) : fetchExclusions()}
                            className="p-2.5 bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-400 hover:text-white hover:bg-white/[0.06] hover:border-white/[0.13] transition-all duration-200"
                            title="Refresh"
                        >
                            <RefreshCw className={`w-4 h-4 ${loading || refreshing ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                }
            >
                {!loading && (
                    <span className="flex items-center gap-1.5 text-xs text-gray-500 bg-white/5 px-2.5 py-1 rounded-full border border-white/5">
                        <Database className="w-3 h-3" />
                        {totalAll.toLocaleString()} total patterns
                    </span>
                )}
            </PageHeading>

            {/* Add Baseline Form */}
            <AnimatePresence>
                {showAddForm && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <GlassCard className="p-4 border-l-4 border-l-green-500/50">
                            <div className="flex items-end gap-3">
                                <div className="flex-1 min-w-0">
                                    <label className="text-[11px] text-gray-400 uppercase tracking-widest font-semibold mb-1.5 block">Pattern</label>
                                    <input
                                        type="text"
                                        value={addPattern}
                                        onChange={(e) => setAddPattern(e.target.value)}
                                        onKeyDown={(e) => e.key === 'Enter' && handleAddBaseline()}
                                        placeholder="e.g. /home/user/.config/Code/** or 10.0.0.0/8:443"
                                        className="w-full px-3 py-2 bg-white/[0.04] border border-white/[0.08] rounded-xl text-sm text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:border-green-500/40 focus:bg-green-500/[0.03] transition-all"
                                    />
                                </div>
                                <div>
                                    <label className="text-[11px] text-gray-400 uppercase tracking-widest font-semibold mb-1.5 block">Type</label>
                                    <div className="flex gap-1">
                                        {Object.entries(signalTypeConfig).map(([key, cfg]) => {
                                            const Icon = cfg.icon;
                                            return (
                                                <button
                                                    key={key}
                                                    onClick={() => setAddSignalType(key)}
                                                    className={`px-2.5 py-2 rounded-lg text-xs font-semibold transition-all duration-200 border flex items-center gap-1.5 ${
                                                        addSignalType === key
                                                            ? `${cfg.bg} ${cfg.border} ${cfg.color}`
                                                            : 'bg-white/[0.03] border-white/[0.06] text-gray-500 hover:text-gray-300 hover:bg-white/[0.06]'
                                                    }`}
                                                >
                                                    <Icon className="w-3.5 h-3.5" />
                                                    {cfg.label}
                                                </button>
                                            );
                                        })}
                                    </div>
                                </div>
                                <div>
                                    <label className="text-[11px] text-gray-400 uppercase tracking-widest font-semibold mb-1.5 block">Agent <span className="text-gray-600 normal-case">(optional)</span></label>
                                    <select
                                        value={addAiType}
                                        onChange={(e) => setAddAiType(e.target.value)}
                                        className="px-2.5 py-2 bg-white/[0.04] border border-white/[0.08] rounded-lg text-xs text-gray-300 focus:outline-none focus:border-green-500/40 transition-all cursor-pointer"
                                    >
                                        <option value="">Any Agent</option>
                                        {Object.entries(AI_AGENT_NAMES).map(([key, label]) => (
                                            <option key={key} value={key}>{label}</option>
                                        ))}
                                    </select>
                                </div>
                                <button
                                    onClick={handleAddBaseline}
                                    disabled={!addPattern.trim() || addingBaseline}
                                    className="px-4 py-2 bg-green-500/20 hover:bg-green-500/30 text-green-300 border border-green-500/30 hover:border-green-500/50 rounded-xl text-sm font-semibold transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 whitespace-nowrap"
                                >
                                    <ShieldCheck className="w-4 h-4" />
                                    Allow
                                </button>
                                <button
                                    onClick={() => { setShowAddForm(false); setAddPattern(''); setAddAiType(''); }}
                                    className="p-2 text-gray-500 hover:text-gray-300 transition-colors"
                                >
                                    <X className="w-4 h-4" />
                                </button>
                            </div>
                        </GlassCard>
                    </motion.div>
                )}
            </AnimatePresence>

            {activeTab === 'learned' && (
                <>
                    {/* Category tiles */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
                        {/* All tile */}
                        <motion.button
                            custom={0} variants={cardVariants} initial="hidden" animate="visible"
                            whileHover={{ scale: 1.04, y: -2 }}
                            whileTap={{ scale: 0.97 }}
                            onClick={() => setFilter('')}
                            className={`group relative flex flex-col items-center gap-1.5 px-3 py-4 rounded-2xl text-center transition-all duration-300 border-2 overflow-hidden ${
                                filter === ''
                                    ? 'border-white/30 shadow-lg shadow-white/10 ring-1 ring-white/10'
                                    : 'border-white/[0.12] hover:border-white/25'
                            }`}
                            style={{
                                background: filter === ''
                                    ? 'linear-gradient(to bottom, rgba(255,255,255,0.14), rgba(255,255,255,0.04))'
                                    : 'linear-gradient(to bottom, rgba(255,255,255,0.06), rgba(255,255,255,0.02))',
                            }}
                        >
                            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(circle at 50% 0%, rgba(255,255,255,0.08), transparent 70%)' }} />
                            {filter === '' && <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent 10%, rgba(255,255,255,0.5), transparent 90%)' }} />}
                            <div className={`relative p-2 rounded-xl transition-all duration-300 ${filter === '' ? 'bg-white/15' : 'bg-white/[0.08] group-hover:bg-white/12'}`}>
                                <Database className={`w-4 h-4 transition-colors duration-300 ${filter === '' ? 'text-white' : 'text-gray-400 group-hover:text-gray-200'}`} />
                            </div>
                            <span className={`text-[10px] font-bold uppercase tracking-wider transition-colors duration-300 ${filter === '' ? 'text-white/90' : 'text-gray-400 group-hover:text-gray-300'}`}>All</span>
                            <span className={`text-xl font-extrabold tabular-nums leading-none transition-colors duration-300 ${filter === '' ? 'text-white' : 'text-gray-300'}`}>{summaryTotal.toLocaleString()}</span>
                        </motion.button>
                        {/* Per-type tiles */}
                        {signalTypes.map((type, idx) => {
                            const cfg = signalTypeConfig[type];
                            const Icon = cfg.icon;
                            const count = typeCounts[type];
                            const isActive = filter === type;
                            return (
                                <motion.button
                                    key={type}
                                    custom={idx + 1} variants={cardVariants} initial="hidden" animate="visible"
                                    whileHover={{ scale: 1.04, y: -2 }}
                                    whileTap={{ scale: 0.97 }}
                                    onClick={() => setFilter(isActive ? '' : type)}
                                    className={`group relative flex flex-col items-center gap-1.5 px-3 py-4 rounded-2xl text-center transition-all duration-300 border-2 overflow-hidden ${
                                        isActive
                                            ? 'shadow-lg ring-1'
                                            : 'hover:shadow-md'
                                    }`}
                                    style={{
                                        background: isActive
                                            ? `linear-gradient(to bottom, ${cfg.hex}20, ${cfg.hex}0a)`
                                            : `linear-gradient(to bottom, ${cfg.hex}0c, ${cfg.hex}04)`,
                                        borderColor: isActive ? `${cfg.hex}50` : `${cfg.hex}30`,
                                        boxShadow: isActive ? `0 8px 30px ${cfg.hex}20` : undefined,
                                        // @ts-expect-error ring color via CSS var
                                        '--tw-ring-color': isActive ? `${cfg.hex}25` : undefined,
                                    }}
                                >
                                    {/* Radial glow — always visible, brighter when active */}
                                    <div className="absolute inset-0 pointer-events-none transition-opacity duration-300" style={{ background: `radial-gradient(circle at 50% 0%, ${cfg.hex}${isActive ? '20' : '0c'}, transparent 70%)` }} />
                                    {/* Top edge highlight */}
                                    <div className="absolute inset-x-0 top-0 h-px transition-opacity duration-300" style={{ background: `linear-gradient(90deg, transparent 10%, ${cfg.hex}${isActive ? '90' : '30'}, transparent 90%)` }} />
                                    <div
                                        className="relative p-2 rounded-xl transition-all duration-300"
                                        style={{ background: `${cfg.hex}${isActive ? '25' : '12'}`, boxShadow: isActive ? `0 0 12px ${cfg.hex}20` : undefined }}
                                    >
                                        <Icon className={`w-4 h-4 transition-colors duration-300 ${isActive ? cfg.color : cfg.color + ' opacity-60 group-hover:opacity-90'}`} />
                                    </div>
                                    <span className={`text-[10px] font-bold uppercase tracking-wider transition-colors duration-300 ${isActive ? cfg.color : cfg.color + ' opacity-50 group-hover:opacity-80'}`}>{cfg.label}</span>
                                    <span className={`text-xl font-extrabold tabular-nums leading-none transition-colors duration-300 ${isActive ? 'text-white' : count > 0 ? 'text-gray-300' : 'text-gray-600'}`}>{count.toLocaleString()}</span>
                                </motion.button>
                            );
                        })}
                    </div>

                    {/* Filters row */}
                    <div className="flex items-center gap-3 flex-wrap">
                        {/* Manual Only toggle */}
                        <button
                            onClick={() => setShowManualOnly(!showManualOnly)}
                            className={`flex items-center gap-2 px-3.5 py-2.5 rounded-2xl text-sm font-semibold border-2 transition-all duration-200 ${
                                showManualOnly
                                    ? 'bg-green-500/10 border-green-500/30 text-green-300'
                                    : 'bg-[#0d1117]/60 border-white/[0.07] text-gray-400 hover:text-white hover:bg-white/[0.06] hover:border-white/[0.13]'
                            }`}
                        >
                            <UserCheck className="w-3.5 h-3.5" />
                            <span>Manual Only</span>
                            {manualCount > 0 && (
                                <span className={`px-1.5 py-0.5 text-xs rounded-full tabular-nums ${showManualOnly ? 'bg-green-500/20 text-green-300' : 'bg-white/[0.06] text-gray-500'}`}>
                                    {manualCount}
                                </span>
                            )}
                        </button>

                        {/* Pattern search */}
                        <div className="relative">
                            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
                            <input
                                type="text"
                                placeholder="Search patterns..."
                                value={patternSearch}
                                onChange={(e) => setPatternSearch(e.target.value)}
                                className="pl-8 pr-8 py-2.5 text-sm bg-[#0d1117]/60 border-2 border-white/[0.07] rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500/40 focus:ring-1 focus:ring-blue-500/20 w-64 transition-all"
                            />
                            {patternSearch && (
                                <button onClick={() => setPatternSearch('')} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
                                    <X className="w-3.5 h-3.5" />
                                </button>
                            )}
                        </div>

                        {/* AI Agent filter dropdown */}
                        {uniqueAgents.length > 0 && (
                            <div className="relative">
                                <button
                                    onClick={() => setAgentDropdownOpen(!agentDropdownOpen)}
                                    className={`flex items-center gap-2 px-3.5 py-2.5 rounded-2xl text-sm font-semibold border-2 transition-all duration-200 ${
                                        agentFilter !== ''
                                            ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                                            : 'bg-[#0d1117]/60 border-white/[0.07] text-gray-400 hover:text-white hover:bg-white/[0.06] hover:border-white/[0.13]'
                                    }`}
                                >
                                    <Bot className="w-3.5 h-3.5" />
                                    <span>
                                        {agentFilter === '' ? 'All Agents' : agentFilter === '__unscoped__' ? 'Unscoped (any agent)' : agentFilter}
                                    </span>
                                    <ChevronDown className={`w-3.5 h-3.5 transition-transform ${agentDropdownOpen ? 'rotate-180' : ''}`} />
                                </button>
                                {agentDropdownOpen && (
                                    <>
                                        <div className="fixed inset-0 z-10" onClick={() => setAgentDropdownOpen(false)} />
                                        <div className="absolute top-full left-0 mt-1 z-20 bg-[#1a1a2e] border border-white/10 rounded-lg shadow-xl min-w-[200px] py-1 max-h-64 overflow-y-auto">
                                            <button
                                                onClick={() => { setAgentFilter(''); setAgentDropdownOpen(false); }}
                                                className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                                                    agentFilter === '' ? 'bg-cyan-500/10 text-cyan-300' : 'text-gray-300 hover:bg-white/5'
                                                }`}
                                            >
                                                All Agents
                                            </button>
                                            {uniqueAgents.map(agent => (
                                                <button
                                                    key={agent || '__unscoped__'}
                                                    onClick={() => { setAgentFilter(agent || '__unscoped__'); setAgentDropdownOpen(false); }}
                                                    className={`w-full text-left px-4 py-2 text-sm transition-colors ${
                                                        (agent === '' ? '__unscoped__' : agent) === agentFilter
                                                            ? 'bg-cyan-500/10 text-cyan-300'
                                                            : 'text-gray-300 hover:bg-white/5'
                                                    }`}
                                                >
                                                    {agent || 'Unscoped (any agent)'}
                                                </button>
                                            ))}
                                        </div>
                                    </>
                                )}
                            </div>
                        )}

                        {/* Active filters indicator */}
                        {(agentFilter !== '' || patternSearch || showManualOnly) && (
                            <div className="flex items-center gap-2 text-sm">
                                <Filter className="w-3.5 h-3.5 text-gray-500" />
                                {showManualOnly && (
                                    <span className="px-2 py-0.5 rounded text-xs border bg-green-500/10 border-green-500/30 text-green-300">
                                        Manual Only
                                    </span>
                                )}
                                {agentFilter !== '' && (
                                    <span className="px-2 py-0.5 rounded text-xs border bg-cyan-500/10 border-cyan-500/30 text-cyan-300">
                                        {agentFilter === '__unscoped__' ? 'Unscoped' : agentFilter}
                                    </span>
                                )}
                                {patternSearch && (
                                    <span className="px-2 py-0.5 rounded text-xs border bg-purple-500/10 border-purple-500/30 text-purple-300">
                                        &quot;{patternSearch}&quot;
                                    </span>
                                )}
                                <span className="text-xs text-gray-500 tabular-nums">{filteredBaselines.length} results</span>
                                <button
                                    onClick={() => { setFilter(''); setAgentFilter(''); setPatternSearch(''); setShowManualOnly(false); }}
                                    className="text-gray-500 hover:text-white text-xs transition-colors"
                                >
                                    Clear all
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Baselines Table */}
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
                                <span>Loading baselines...</span>
                            </motion.div>
                        ) : filteredBaselines.length === 0 ? (
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
                                        <Database className="w-14 h-14 text-gray-600 mx-auto mb-4" />
                                    </motion.div>
                                    {visibleBaselines.length === 0 ? (
                                        <>
                                            <h3 className="text-xl font-semibold mb-2">
                                                {showManualOnly ? 'No Manually Confirmed Baselines Yet' : 'No Baselines Yet'}
                                            </h3>
                                            <p className="text-gray-400 max-w-md mx-auto">
                                                {showManualOnly
                                                    ? 'Use "Allow Always" on findings or the "+" button to manually confirm safe patterns.'
                                                    : 'Patterns will appear here as the detection engine observes and learns from activity.'}
                                            </p>
                                        </>
                                    ) : (
                                        <>
                                            <h3 className="text-xl font-semibold mb-2">No Matches</h3>
                                            <p className="text-gray-400">No baselines match the selected filters</p>
                                            <button
                                                onClick={() => { setFilter(''); setAgentFilter(''); setPatternSearch(''); setShowManualOnly(false); }}
                                                className="mt-4 px-4 py-2 text-sm font-semibold bg-white/5 border border-white/10 rounded-xl text-gray-300 hover:bg-white/10 hover:shadow-lg hover:shadow-white-500/5 hover:border-white/40 transition-all duration-200"
                                            >
                                                Clear filters
                                            </button>
                                        </>
                                    )}
                                </GlassCard>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="table"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                                className="space-y-5"
                            >
                                {/* File tree explorer */}
                                {fileTree.length > 0 && (
                                    <GlassCard className="overflow-hidden" glow="#3b82f6">
                                        <div className="border-b border-white/[0.06] bg-white/[0.015]">
                                            <div className="flex items-center justify-between px-5 py-3.5">
                                                <div className="flex items-center gap-2.5">
                                                    <div className="p-1.5 rounded-lg bg-blue-500/10 border border-blue-500/20">
                                                        <Folder className="w-3.5 h-3.5 text-blue-400" />
                                                    </div>
                                                    <span className="text-[11px] text-gray-300 font-semibold uppercase tracking-widest">File Baselines</span>
                                                    {refreshing && (
                                                        <span className="flex items-center gap-1.5 text-[10px] text-blue-400 bg-blue-500/10 px-2.5 py-0.5 rounded-full border border-blue-500/20 animate-pulse">
                                                            <Loader2 className="w-3 h-3 animate-spin" />
                                                            Updating...
                                                        </span>
                                                    )}
                                                    <span className="text-[10px] text-gray-400 bg-white/[0.06] px-2.5 py-0.5 rounded-full tabular-nums border border-white/[0.04]">
                                                        {fileTree.reduce((s, n) => s + n.totalFiles, 0)} files in {fileTree.length} {fileTree.length === 1 ? 'tree' : 'trees'}
                                                    </span>
                                                </div>
                                                <div className="flex items-center gap-3.5 text-[10px] text-gray-500">
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-green-500" /> &lt;1h</span>
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-yellow-500" /> &lt;24h</span>
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-gray-500" /> older</span>
                                                </div>
                                            </div>
                                            {/* Column headers */}
                                            <div className="flex items-center px-5 py-2 text-[11px] text-gray-400 uppercase tracking-widest font-semibold border-t border-white/[0.04] bg-white/[0.01]">
                                                <span className="flex-1">Directory</span>
                                                <div className="shrink-0 flex items-center gap-6">
                                                    <span className="w-[180px]">Latest File</span>
                                                    <span className="w-[120px] text-right">Actions</span>
                                                    <span className="w-[220px] text-center">Agent</span>
                                                    <span className="w-[60px] text-right">Hits</span>
                                                    <span className="w-[140px] text-right">Last Seen</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div className="py-2">
                                            {fileTree.map((node, i) => (
                                                <TreeRows
                                                    key={`tree-${i}-${node.fullPath}`}
                                                    node={node}
                                                    depth={0}
                                                    maxHits={maxHits}
                                                    expandedDirs={expandedDirs}
                                                    setExpandedDirs={setExpandedDirs}
                                                    setSuspendTarget={setSuspendTarget}
                                                    setDeleteTarget={setDeleteTarget}
                                                    setAddDirTarget={setAddDirTarget}

                                                    formatDate={formatDate}
                                                    formatExpiresAt={formatExpiresAt}
                                                    freshnessColor={freshnessColor}
                                                    isLast={i === fileTree.length - 1}
                                                />
                                            ))}
                                        </div>
                                    </GlassCard>
                                )}

                                {/* Network baselines grouped by port */}
                                {networkPortGroups.length > 0 && (
                                    <GlassCard className="overflow-hidden" glow="#f97316">
                                        <div className="border-b border-white/[0.06] bg-white/[0.015]">
                                            <div className="flex items-center justify-between px-5 py-3.5">
                                                <div className="flex items-center gap-2.5">
                                                    <div className="p-1.5 rounded-lg bg-orange-500/10 border border-orange-500/20">
                                                        <Wifi className="w-3.5 h-3.5 text-orange-400" />
                                                    </div>
                                                    <span className="text-[11px] text-gray-300 font-semibold uppercase tracking-widest">Network Baselines</span>
                                                    <span className="text-[10px] text-gray-400 bg-white/[0.06] px-2.5 py-0.5 rounded-full tabular-nums border border-white/[0.04]">
                                                        {networkPortGroups.reduce((s, g) => s + g.subnets.length, 0)} subnets across {networkPortGroups.length} {networkPortGroups.length === 1 ? 'port' : 'ports'}
                                                    </span>
                                                </div>
                                                <div className="flex items-center gap-3.5 text-[10px] text-gray-500">
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-green-500" /> &lt;1h</span>
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-yellow-500" /> &lt;24h</span>
                                                    <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-gray-500" /> older</span>
                                                </div>
                                            </div>
                                            {/* Column headers */}
                                            <div className="flex items-center px-5 py-2 text-[11px] text-gray-400 uppercase tracking-widest font-semibold border-t border-white/[0.04] bg-white/[0.01]">
                                                <span className="flex-1">Port / Subnet</span>
                                                <div className="shrink-0 flex items-center gap-6">
                                                    <span className="w-[240px] text-center">Agent</span>
                                                    <span className="w-[90px] text-right">Hits</span>
                                                    <span className="w-[150px] text-right">Last Seen</span>
                                                    <span className="w-[80px]" />
                                                </div>
                                            </div>
                                        </div>
                                        <div className="py-1.5">
                                            {networkPortGroups.map(group => (
                                                <NetworkPortGroupRow
                                                    key={`netgrp-${group.port}`}
                                                    group={group}
                                                    maxHits={maxHits}
                                                    expandedDirs={expandedDirs}
                                                    setExpandedDirs={setExpandedDirs}
                                                    setSuspendTarget={setSuspendTarget}
                                                    setDeleteTarget={setDeleteTarget}
                                                    formatDate={formatDate}
                                                    formatExpiresAt={formatExpiresAt}
                                                    freshnessColor={freshnessColor}
                                                    domainMap={domainMap}
                                                    domainLoading={domainLoading}
                                                    onResolveDomain={handleResolveDomain}
                                                />
                                            ))}
                                        </div>
                                    </GlassCard>
                                )}

                                {/* Per-type section cards */}
                                {[
                                    { key: 'binary', rows: binaryRows, title: 'Binary Baselines', icon: Cpu, color: 'text-green-400', hex: '#22c55e', bgIcon: 'bg-green-500/10', borderIcon: 'border-green-500/20' },
                                    { key: 'command', rows: commandRows, title: 'Command Baselines', icon: Terminal, color: 'text-teal-400', hex: '#2dd4bf', bgIcon: 'bg-teal-500/10', borderIcon: 'border-teal-500/20' },
                                    { key: 'dns', rows: dnsRows, title: 'DNS Baselines', icon: Globe, color: 'text-purple-400', hex: '#a855f7', bgIcon: 'bg-purple-500/10', borderIcon: 'border-purple-500/20' },
                                    { key: 'container', rows: containerRows, title: 'Container Baselines', icon: Database, color: 'text-red-400', hex: '#ef4444', bgIcon: 'bg-red-500/10', borderIcon: 'border-red-500/20' },
                                    { key: 'fileActivity', rows: fileActivityRows, title: 'File Activity Baselines', icon: FileText, color: 'text-sky-400', hex: '#38bdf8', bgIcon: 'bg-sky-500/10', borderIcon: 'border-sky-500/20' },
                                    { key: 'other', rows: otherRows, title: 'Other Baselines', icon: ShieldCheck, color: 'text-gray-400', hex: '#9ca3af', bgIcon: 'bg-white/[0.06]', borderIcon: 'border-white/[0.08]' },
                                ].filter(section => section.rows.length > 0).map(section => {
                                    const SectionIcon = section.icon;
                                    return (
                                        <GlassCard key={section.key} className="overflow-hidden" glow={section.hex}>
                                            <div className="border-b border-white/[0.06] bg-white/[0.015]">
                                                <div className="flex items-center justify-between px-5 py-3.5">
                                                    <div className="flex items-center gap-2.5">
                                                        <div className={`p-1.5 rounded-lg ${section.bgIcon} border ${section.borderIcon}`}>
                                                            <SectionIcon className={`w-3.5 h-3.5 ${section.color}`} />
                                                        </div>
                                                        <span className="text-[11px] text-gray-300 font-semibold uppercase tracking-widest">{section.title}</span>
                                                        <span className="text-[10px] text-gray-400 bg-white/[0.06] px-2.5 py-0.5 rounded-full tabular-nums border border-white/[0.04]">
                                                            {section.rows.length} {section.rows.length === 1 ? 'pattern' : 'patterns'}
                                                        </span>
                                                    </div>
                                                </div>
                                                <div className="flex items-center px-5 py-2 text-[11px] text-gray-400 uppercase tracking-widest font-semibold border-t border-white/[0.04] bg-white/[0.01]">
                                                    <span className="flex-1">Pattern</span>
                                                    <div className="shrink-0 flex items-center gap-6">
                                                        <span className="w-[160px]">Suppresses</span>
                                                        <span className="w-[100px] text-center">Agent</span>
                                                        <span className="w-[70px] text-right">Hits</span>
                                                        <span className="w-[130px] text-right">Last Seen</span>
                                                        <span className="w-[150px] text-center">Actions</span>
                                                    </div>
                                                </div>
                                            </div>
                                            <div className="divide-y divide-white/[0.04]">
                                                {section.rows.map((baseline, idx) => {
                                                    const cfg = signalTypeConfig[baseline.signal_type] || signalTypeConfig.file_pattern;
                                                    const aiLabel = baseline.ai_type ? aiAgentDisplayName(baseline.ai_type) : null;
                                                    const hitPct = maxHits > 0 ? (baseline.hit_count / maxHits) * 100 : 0;
                                                    const freshColor = freshnessColor(baseline.last_seen);
                                                    const expiryLabel = formatExpiresAt(baseline.expires_at, baseline.suspended_until);
                                                    const isExpired = expiryLabel === 'Expired';
                                                    return (
                                                        <div key={`${section.key}-${baseline.id}-${idx}`} className="flex items-center px-5 py-3 hover:bg-white/[0.03] transition-colors">
                                                            <div className="flex-1 min-w-0">
                                                                <div className="flex items-center gap-2">
                                                                    <code className="text-sm text-gray-200 font-mono bg-white/[0.04] px-2 py-0.5 rounded break-all leading-relaxed" title={baseline.pattern}>
                                                                        {baseline.pattern}
                                                                    </code>
                                                                    {baseline.source === 'user_confirmed' && (
                                                                        <span className="shrink-0 inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-green-500/10 text-green-400 border border-green-500/20">
                                                                            <UserCheck className="w-3 h-3" />
                                                                            Confirmed
                                                                        </span>
                                                                    )}
                                                                </div>
                                                                <p className="text-[11px] text-gray-600 mt-0.5 truncate">{cfg.description}</p>
                                                            </div>
                                                            <div className="shrink-0 flex items-center gap-6">
                                                                <div className="w-[160px]">
                                                                    <div className="flex flex-wrap gap-1">
                                                                        {cfg.suppresses.split(', ').map(rule => (
                                                                            <code key={rule} className="text-[10px] text-yellow-400/70 font-mono bg-yellow-500/[0.06] px-1.5 py-0.5 rounded border border-yellow-500/15">{rule}</code>
                                                                        ))}
                                                                    </div>
                                                                </div>
                                                                <div className="w-[100px] text-center">
                                                                    {aiLabel ? (
                                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"><Bot className="w-3 h-3 text-cyan-400/60" />{aiLabel}</span>
                                                                    ) : (
                                                                        <span className="text-xs text-gray-600 italic">Any</span>
                                                                    )}
                                                                </div>
                                                                <div className="w-[70px] text-right">
                                                                    <span className={`text-sm font-bold tabular-nums ${baseline.hit_count > 100 ? 'text-green-400' : baseline.hit_count > 10 ? 'text-yellow-400' : 'text-gray-400'}`}>{baseline.hit_count.toLocaleString()}</span>
                                                                    <div className="w-full h-[2px] bg-white/[0.04] rounded-full overflow-hidden mt-1">
                                                                        <div className="h-full rounded-full" style={{ width: `${hitPct}%`, background: baseline.hit_count > 100 ? '#22c55e' : baseline.hit_count > 10 ? '#eab308' : '#475569' }} />
                                                                    </div>
                                                                </div>
                                                                <div className="w-[130px] text-right">
                                                                    <div className="flex items-center justify-end gap-1.5">
                                                                        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: freshColor }} />
                                                                        <span className="text-xs text-gray-300">{formatDate(baseline.last_seen)}</span>
                                                                    </div>
                                                                    {expiryLabel && (
                                                                        <span className={`text-[10px] px-1 py-0.5 rounded mt-0.5 inline-block ${isExpired ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>{expiryLabel}</span>
                                                                    )}
                                                                </div>
                                                                <div className="w-[150px] flex items-center justify-center gap-1.5">
                                                                    <button onClick={() => setSuspendTarget(baseline.id)} className="px-2 py-1 bg-amber-500/[0.08] hover:bg-amber-500/20 text-amber-400/70 hover:text-amber-300 border border-amber-500/10 hover:border-amber-500/40 rounded-lg text-[11px] font-semibold transition-all flex items-center gap-1"><Clock className="w-3 h-3" />Suspend</button>
                                                                    <button onClick={() => setDeleteTarget(baseline.id)} className="px-2 py-1 bg-red-500/[0.06] hover:bg-red-500/15 text-red-400/60 hover:text-red-300 border border-red-500/10 hover:border-red-500/40 rounded-lg text-[11px] font-semibold transition-all flex items-center gap-1"><Trash2 className="w-3 h-3" />Remove</button>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </GlassCard>
                                    );
                                })}
                            </motion.div>
                        )}
                    </AnimatePresence>

                    {/* Infinite scroll sentinel */}
                    <div ref={sentinelRef} className="h-1" />
                    {loadingMore && (
                        <div className="flex items-center justify-center py-4 text-gray-400 gap-2">
                            <Loader2 className="w-4 h-4 animate-spin" />
                            <span className="text-sm">Loading more baselines...</span>
                        </div>
                    )}
                    {!loading && !hasMore && baselines.length > 0 && (
                        <p className="text-center text-xs text-gray-600 py-2">
                            {baselines.length} baselines loaded
                        </p>
                    )}
                </>
            )}

            {activeTab === 'allowlist' && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    className="space-y-6"
                >
                    {/* Add domain form */}
                    <GlassCard className="p-6">
                        <h3 className="text-sm font-semibold text-gray-300 mb-3">Add Safe Domain</h3>
                        <div className="flex items-end gap-3">
                            <div className="flex-1 max-w-sm">
                                <label className="block text-xs text-gray-500 mb-1">Domain</label>
                                <input
                                    type="text"
                                    value={newDomain}
                                    onChange={e => setNewDomain(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
                                    placeholder="example.com"
                                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/30"
                                />
                            </div>
                            <div className="flex-1 max-w-md">
                                <label className="block text-xs text-gray-500 mb-1">Description (optional)</label>
                                <input
                                    type="text"
                                    value={newDomainDesc}
                                    onChange={e => setNewDomainDesc(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleAddDomain()}
                                    placeholder="AI provider API"
                                    className="w-full px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-purple-500/50 focus:ring-1 focus:ring-purple-500/30"
                                />
                            </div>
                            <button
                                onClick={handleAddDomain}
                                disabled={!newDomain.trim() || addingDomain}
                                className="px-4 py-2 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/30 hover:border-purple-500/40 hover:shadow-lg hover:shadow-purple-500/5 rounded-xl text-sm font-semibold transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
                            >
                                {addingDomain ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                                <span>Add</span>
                            </button>
                        </div>
                    </GlassCard>

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
                                <span>Loading safe domains...</span>
                            </motion.div>
                        ) : safeDomains.length === 0 ? (
                            <motion.div
                                key="empty"
                                initial={{ opacity: 0, scale: 0.95 }}
                                animate={{ opacity: 1, scale: 1 }}
                                exit={{ opacity: 0 }}
                            >
                                <GlassCard className="p-12 text-center border-purple-500/30">
                                    <motion.div
                                        initial={{ scale: 0 }}
                                        animate={{ scale: 1 }}
                                        transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
                                    >
                                        <ShieldCheck className="w-14 h-14 text-gray-600 mx-auto mb-4" />
                                    </motion.div>
                                    <h3 className="text-xl font-semibold mb-2">No Safe Domains Configured</h3>
                                    <p className="text-gray-400 max-w-md mx-auto">Add domains above to suppress findings for known-safe AI provider connections.</p>
                                </GlassCard>
                            </motion.div>
                        ) : (
                            <motion.div
                                key="table"
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                exit={{ opacity: 0 }}
                            >
                                <GlassCard className="overflow-hidden border-t-4 border-t-purple-500/50">
                                    <div className="p-6 border-b border-white/5 bg-white/[0.02]">
                                        <h3 className="text-lg font-semibold flex items-center text-white">
                                            <ShieldCheck className="w-5 h-5 mr-2 text-purple-400" />
                                            Silence AI Finding Noise
                                        </h3>
                                        <p className="text-sm text-gray-400 mt-1">
                                            Connections to these domains by an AI agent are explicitly allowed and will be quietly suppressed by the detection engine.
                                        </p>
                                    </div>
                                    <div className="overflow-x-auto">
                                        <table className="w-full">
                                            <thead>
                                                <tr className="border-b border-white/10 bg-white/[0.01]">
                                                    <th className="text-left text-xs text-gray-400 font-medium px-6 py-4 uppercase tracking-wider">Domain</th>
                                                    <th className="text-left text-xs text-gray-400 font-medium px-6 py-4 uppercase tracking-wider">Description</th>
                                                    <th className="text-right text-xs text-gray-400 font-medium px-6 py-4 uppercase tracking-wider">Added</th>
                                                    <th className="text-right text-xs text-gray-400 font-medium px-6 py-4 uppercase tracking-wider w-20">Actions</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-white/5">
                                                {safeDomains.map((domain) => (
                                                    <tr key={domain.id} className="hover:bg-white/5 transition-colors group">
                                                        <td className="px-6 py-4">
                                                            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-lg text-sm bg-purple-500/10 border-purple-500/30 border text-purple-300 font-mono">
                                                                {domain.domain}
                                                            </span>
                                                        </td>
                                                        <td className="px-6 py-4 text-gray-300">
                                                            {domain.description || "\u2014"}
                                                        </td>
                                                        <td className="px-6 py-4 text-right text-sm text-gray-500">
                                                            {formatDate(domain.created_at)}
                                                        </td>
                                                        <td className="px-6 py-4 text-right">
                                                            <button
                                                                onClick={() => setDeleteDomainTarget(domain.id)}
                                                                className="p-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-xl transition-all duration-200 opacity-0 group-hover:opacity-100"
                                                                title="Remove domain"
                                                            >
                                                                <Trash2 className="w-3.5 h-3.5" />
                                                            </button>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    </div>
                                </GlassCard>
                            </motion.div>
                        )}
                    </AnimatePresence>
                </motion.div>
            )}

            {activeTab === 'exclusions' && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    className="space-y-6"
                >
                    <AnimatePresence mode="wait">
                        {loading ? (
                            <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                                className="flex items-center justify-center py-20 text-gray-400 gap-2">
                                <Loader2 className="w-5 h-5 animate-spin" />
                                <span>Loading exclusions...</span>
                            </motion.div>
                        ) : exclusions.length === 0 && suspendedBaselines.length === 0 ? (
                            <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                                className="flex flex-col items-center justify-center py-20 text-gray-500 gap-3">
                                <ShieldCheck className="w-12 h-12 text-gray-600" />
                                <div className="text-center">
                                    <p className="text-lg font-medium text-gray-400">No Exclusions</p>
                                    <p className="text-sm mt-1">When you delete or suspend a baseline, it will appear here.</p>
                                </div>
                            </motion.div>
                        ) : (
                            <motion.div key="sections" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-5">
                                {/* Suspended Baselines — grouped by type */}
                                {suspendedBaselines.length > 0 && (() => {
                                    const suspendedByType = new Map<string, Baseline[]>();
                                    for (const b of suspendedBaselines) {
                                        const key = (b.signal_type === 'command_binary') ? 'binary' : b.signal_type;
                                        const list = suspendedByType.get(key) || [];
                                        list.push(b);
                                        suspendedByType.set(key, list);
                                    }
                                    const sectionConfigs: { key: string; hex: string; color: string; icon: React.ElementType; label: string }[] = [
                                        { key: 'file_pattern', hex: '#3b82f6', color: 'text-blue-400', icon: FileText, label: 'File Pattern' },
                                        { key: 'binary', hex: '#22c55e', color: 'text-green-400', icon: Cpu, label: 'Binary' },
                                        { key: 'command', hex: '#2dd4bf', color: 'text-teal-400', icon: Terminal, label: 'Command' },
                                        { key: 'network_dest', hex: '#f97316', color: 'text-orange-400', icon: Wifi, label: 'Network' },
                                        { key: 'dns_domain', hex: '#a855f7', color: 'text-purple-400', icon: Globe, label: 'DNS' },
                                        { key: 'file_activity', hex: '#38bdf8', color: 'text-sky-400', icon: FileText, label: 'File Activity' },
                                        { key: 'container_escape', hex: '#ef4444', color: 'text-red-400', icon: Database, label: 'Container' },
                                    ];
                                    return (
                                        <div className="space-y-2">
                                            <div className="flex items-center gap-2 px-1">
                                                <Clock className="w-4 h-4 text-amber-400" />
                                                <span className="text-sm font-semibold text-amber-300">Suspended Baselines</span>
                                                <span className="px-1.5 py-0.5 text-xs bg-amber-500/20 text-amber-400 rounded-full tabular-nums">{suspendedBaselines.length}</span>
                                                <span className="text-[11px] text-gray-600 ml-1">Detection engine will flag these until suspension expires</span>
                                            </div>
                                            <div className="space-y-4">
                                                {sectionConfigs.filter(s => suspendedByType.has(s.key)).map(section => {
                                                    const rows = suspendedByType.get(section.key)!;
                                                    const SIcon = section.icon;
                                                    return (
                                                        <GlassCard key={`susp-${section.key}`} className="overflow-hidden" glow={section.hex}>
                                                            <div className="border-b border-white/[0.06] bg-white/[0.015]">
                                                                <div className="flex items-center px-5 py-3">
                                                                    <div className="flex items-center gap-2.5">
                                                                        <div className="p-1.5 rounded-lg" style={{ background: `${section.hex}15`, borderColor: `${section.hex}30` }}>
                                                                            <SIcon className={`w-3.5 h-3.5 ${section.color}`} />
                                                                        </div>
                                                                        <span className="text-[11px] text-gray-300 font-semibold uppercase tracking-widest">{section.label}</span>
                                                                        <span className="text-[10px] text-gray-400 bg-white/[0.06] px-2.5 py-0.5 rounded-full tabular-nums border border-white/[0.04]">
                                                                            {rows.length} {rows.length === 1 ? 'suspended' : 'suspended'}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center px-5 py-2 text-[11px] text-gray-400 uppercase tracking-widest font-semibold border-t border-white/[0.04] bg-white/[0.01]">
                                                                    <span className="flex-1">Pattern</span>
                                                                    <div className="shrink-0 flex items-center gap-6">
                                                                        <span className="w-[100px] text-center">Agent</span>
                                                                        <span className="w-[130px] text-right">Expires</span>
                                                                        <span className="w-[100px] text-center">Actions</span>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            <div className="divide-y divide-white/[0.04]">
                                                                {rows.map((baseline, idx) => {
                                                                    const aiLabel = baseline.ai_type ? aiAgentDisplayName(baseline.ai_type) : null;
                                                                    const expiryLabel = formatExpiresAt(baseline.expires_at, baseline.suspended_until);
                                                                    return (
                                                                        <div key={`susp-${baseline.id}-${idx}`} className="flex items-center px-5 py-3 hover:bg-white/[0.03] transition-colors">
                                                                            <div className="flex-1 min-w-0">
                                                                                <code className="text-sm text-gray-200 font-mono bg-white/[0.04] px-2 py-0.5 rounded break-all leading-relaxed">{baseline.pattern}</code>
                                                                            </div>
                                                                            <div className="shrink-0 flex items-center gap-6">
                                                                                <div className="w-[100px] text-center">
                                                                                    {aiLabel ? (
                                                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"><Bot className="w-3 h-3 text-cyan-400/60" />{aiLabel}</span>
                                                                                    ) : (
                                                                                        <span className="text-xs text-gray-600 italic">Any</span>
                                                                                    )}
                                                                                </div>
                                                                                <div className="w-[130px] text-right">
                                                                                    <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">{expiryLabel}</span>
                                                                                </div>
                                                                                <div className="w-[100px] flex justify-center">
                                                                                    <button onClick={() => setDeleteTarget(baseline.id)} className="px-2 py-1 bg-red-500/[0.06] hover:bg-red-500/15 text-red-400/60 hover:text-red-300 border border-red-500/10 hover:border-red-500/40 rounded-lg text-[11px] font-semibold transition-all flex items-center gap-1"><Trash2 className="w-3 h-3" />Remove</button>
                                                                                </div>
                                                                            </div>
                                                                        </div>
                                                                    );
                                                                })}
                                                            </div>
                                                        </GlassCard>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    );
                                })()}

                                {/* Permanent Exclusions — grouped by type */}
                                {exclusions.length > 0 && (() => {
                                    const exclByType = new Map<string, typeof exclusions>();
                                    for (const e of exclusions) {
                                        const key = (e.signal_type === 'command_binary') ? 'binary' : e.signal_type;
                                        const list = exclByType.get(key) || [];
                                        list.push(e);
                                        exclByType.set(key, list);
                                    }
                                    const sectionConfigs: { key: string; hex: string; color: string; icon: React.ElementType; label: string }[] = [
                                        { key: 'file_pattern', hex: '#3b82f6', color: 'text-blue-400', icon: FileText, label: 'File Pattern' },
                                        { key: 'binary', hex: '#22c55e', color: 'text-green-400', icon: Cpu, label: 'Binary' },
                                        { key: 'command', hex: '#2dd4bf', color: 'text-teal-400', icon: Terminal, label: 'Command' },
                                        { key: 'network_dest', hex: '#f97316', color: 'text-orange-400', icon: Wifi, label: 'Network' },
                                        { key: 'dns_domain', hex: '#a855f7', color: 'text-purple-400', icon: Globe, label: 'DNS' },
                                        { key: 'file_activity', hex: '#38bdf8', color: 'text-sky-400', icon: FileText, label: 'File Activity' },
                                        { key: 'container_escape', hex: '#ef4444', color: 'text-red-400', icon: Database, label: 'Container' },
                                    ];
                                    return (
                                        <div className="space-y-2">
                                            <div className="flex items-center gap-2 px-1">
                                                <ShieldCheck className="w-4 h-4 text-gray-400" />
                                                <span className="text-sm font-semibold text-gray-300">Permanent Exclusions</span>
                                                <span className="px-1.5 py-0.5 text-xs bg-white/10 text-gray-400 rounded-full tabular-nums">{exclusions.length}</span>
                                            </div>
                                            <div className="space-y-4">
                                                {sectionConfigs.filter(s => exclByType.has(s.key)).map(section => {
                                                    const rows = exclByType.get(section.key)!;
                                                    const SIcon = section.icon;
                                                    return (
                                                        <GlassCard key={`excl-${section.key}`} className="overflow-hidden" glow={section.hex}>
                                                            <div className="border-b border-white/[0.06] bg-white/[0.015]">
                                                                <div className="flex items-center px-5 py-3">
                                                                    <div className="flex items-center gap-2.5">
                                                                        <div className="p-1.5 rounded-lg" style={{ background: `${section.hex}15`, borderColor: `${section.hex}30` }}>
                                                                            <SIcon className={`w-3.5 h-3.5 ${section.color}`} />
                                                                        </div>
                                                                        <span className="text-[11px] text-gray-300 font-semibold uppercase tracking-widest">{section.label}</span>
                                                                        <span className="text-[10px] text-gray-400 bg-white/[0.06] px-2.5 py-0.5 rounded-full tabular-nums border border-white/[0.04]">
                                                                            {rows.length} {rows.length === 1 ? 'exclusion' : 'exclusions'}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                                <div className="flex items-center px-5 py-2 text-[11px] text-gray-400 uppercase tracking-widest font-semibold border-t border-white/[0.04] bg-white/[0.01]">
                                                                    <span className="flex-1">Pattern</span>
                                                                    <div className="shrink-0 flex items-center gap-6">
                                                                        <span className="w-[100px] text-center">Agent</span>
                                                                        <span className="w-[130px] text-right">Excluded</span>
                                                                        <span className="w-[100px] text-center">Actions</span>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            <div className="divide-y divide-white/[0.04]">
                                                                {rows.map((excl, idx) => (
                                                                    <div key={`excl-${excl.id}-${idx}`} className="flex items-center px-5 py-3 hover:bg-white/[0.03] transition-colors">
                                                                        <div className="flex-1 min-w-0">
                                                                            <code className="text-sm text-gray-200 font-mono bg-white/[0.04] px-2 py-0.5 rounded break-all leading-relaxed">{excl.pattern}</code>
                                                                        </div>
                                                                        <div className="shrink-0 flex items-center gap-6">
                                                                            <div className="w-[100px] text-center">
                                                                                {excl.ai_type ? (
                                                                                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"><Bot className="w-3 h-3 text-cyan-400/60" />{aiAgentDisplayName(excl.ai_type)}</span>
                                                                                ) : (
                                                                                    <span className="text-xs text-gray-600 italic">Any</span>
                                                                                )}
                                                                            </div>
                                                                            <div className="w-[130px] text-right text-xs text-gray-500">
                                                                                {formatDate(excl.created_at)}
                                                                            </div>
                                                                            <div className="w-[100px] flex justify-center">
                                                                                <button onClick={() => setDeleteExclusionTarget(excl.id)} className="px-2 py-1 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/10 hover:border-amber-500/40 rounded-lg text-[11px] font-semibold transition-all">Re-enable</button>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </GlassCard>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    );
                                })()}
                            </motion.div>
                        )}
                    </AnimatePresence>
                </motion.div>
            )}

            {activeTab === 'never-baseline' && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    className="space-y-6"
                >
                    {/* System-defined rules (collapsible) */}
                    <GlassCard className="overflow-hidden border-t-4 border-t-red-500/40">
                        <button
                            onClick={() => setNbSystemExpanded(!nbSystemExpanded)}
                            className="w-full p-5 border-b border-white/5 bg-white/[0.02] flex items-center justify-between hover:bg-white/[0.04] transition-colors"
                        >
                            <div className="flex items-center gap-3">
                                <div className="p-1.5 rounded-lg bg-red-500/10 border border-red-500/20">
                                    <Ban className="w-4 h-4 text-red-400" />
                                </div>
                                <div className="text-left">
                                    <h3 className="text-sm font-semibold text-white">System-Defined Never-Baseline Rules</h3>
                                    <p className="text-xs text-gray-400 mt-0.5">Built-in security-critical patterns that can never be baselined. These protect against credential theft, C2 channels, and persistence mechanisms.</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                                <span className="text-xs text-gray-500 tabular-nums">{neverBaselines.filter(e => e.source === 'system').length} rules</span>
                                <ChevronDown className={`w-4 h-4 text-gray-400 transition-transform duration-200 ${nbSystemExpanded ? 'rotate-180' : ''}`} />
                            </div>
                        </button>
                        {nbSystemExpanded && (() => {
                            const systemEntries = neverBaselines.filter(e => e.source === 'system');
                            const categories: { key: string; label: string; icon: React.ElementType; color: string; hex: string }[] = [
                                { key: 'file_suffix', label: 'Crypto & Key Files', icon: FileText, color: 'text-yellow-400', hex: '#eab308' },
                                { key: 'file_dir', label: 'Sensitive Directories', icon: Folder, color: 'text-blue-400', hex: '#3b82f6' },
                                { key: 'file_name', label: 'Critical System Files', icon: FileText, color: 'text-orange-400', hex: '#f97316' },
                                { key: 'port', label: 'C2 & Attack Ports', icon: Wifi, color: 'text-red-400', hex: '#ef4444' },
                                { key: 'domain', label: 'Anonymisation & Exfil Domains', icon: Globe, color: 'text-purple-400', hex: '#a855f7' },
                                { key: 'binary', label: 'Attack Tool Binaries', icon: Cpu, color: 'text-cyan-400', hex: '#06b6d4' },
                            ];
                            return (
                                <div className="divide-y divide-white/[0.04]">
                                    {categories.map(cat => {
                                        const items = systemEntries.filter(e => e.category === cat.key);
                                        if (items.length === 0) return null;
                                        const CIcon = cat.icon;
                                        return (
                                            <div key={cat.key} className="px-5 py-4">
                                                <div className="flex items-center gap-2 mb-3">
                                                    <div className="p-1 rounded-md" style={{ background: `${cat.hex}15` }}>
                                                        <CIcon className={`w-3.5 h-3.5 ${cat.color}`} />
                                                    </div>
                                                    <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">{cat.label}</span>
                                                    <span className="text-[10px] text-gray-500 bg-white/[0.05] px-1.5 py-0.5 rounded-full tabular-nums">{items.length}</span>
                                                </div>
                                                <div className="flex flex-wrap gap-1.5">
                                                    {items.map((e, i) => (
                                                        <code key={i} className="text-xs font-mono px-2.5 py-1 rounded-lg bg-white/[0.04] border border-white/[0.06] text-gray-300">{e.pattern}</code>
                                                    ))}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            );
                        })()}
                    </GlassCard>

                    {/* Organization-defined rules */}
                    <GlassCard className="overflow-hidden border-t-4 border-t-orange-500/40">
                        <div className="p-5 border-b border-white/5 bg-white/[0.02]">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                                        <AlertTriangle className="w-4 h-4 text-orange-400" />
                                        Your Organization's Never-Baseline Rules
                                    </h3>
                                    <p className="text-xs text-gray-400 mt-1">Patterns added here will always trigger incidents — they can never be silenced by the learning engine. Existing baselines matching a new rule will be removed.</p>
                                </div>
                            </div>
                        </div>

                        {/* Add form */}
                        <div className="px-5 py-4 border-b border-white/[0.06] bg-white/[0.01]">
                            <div className="flex flex-col gap-3">
                                <div className="flex gap-2 flex-wrap">
                                    {[
                                        { value: 'file_pattern', label: 'File Pattern' },
                                        { value: 'binary', label: 'Binary' },
                                        { value: 'network_dest', label: 'Network Dest' },
                                        { value: 'dns_domain', label: 'DNS Domain' },
                                        { value: 'escalation_cmd', label: 'Escalation Cmd' },
                                        { value: 'persistence_path', label: 'Persistence Path' },
                                    ].map(opt => (
                                        <button key={opt.value} onClick={() => setNbAddSignalType(opt.value)}
                                            className={`px-2.5 py-1 rounded-lg text-xs font-semibold border transition-all ${nbAddSignalType === opt.value ? 'bg-orange-500/20 border-orange-500/40 text-orange-300' : 'bg-white/[0.04] border-white/[0.08] text-gray-400 hover:text-gray-200'}`}>
                                            {opt.label}
                                        </button>
                                    ))}
                                </div>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={nbAddPattern}
                                        onChange={e => setNbAddPattern(e.target.value)}
                                        onKeyDown={e => { if (e.key === 'Enter') handleAddNeverBaseline(); }}
                                        placeholder={nbAddSignalType === 'file_pattern' ? '/path/to/file or /dir/**' : nbAddSignalType === 'network_dest' ? '1.2.3.4:4444 or cidr:port' : nbAddSignalType === 'dns_domain' ? '.onion or evil.com' : 'pattern'}
                                        className="flex-1 min-w-0 bg-white/[0.04] border border-white/[0.10] rounded-xl px-3 py-2 text-sm font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500/40 focus:bg-white/[0.06]"
                                    />
                                    <input
                                        type="text"
                                        value={nbAddDescription}
                                        onChange={e => setNbAddDescription(e.target.value)}
                                        placeholder="Description (optional)"
                                        className="w-56 bg-white/[0.04] border border-white/[0.10] rounded-xl px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500/40 focus:bg-white/[0.06]"
                                    />
                                    <button
                                        onClick={handleAddNeverBaseline}
                                        disabled={!nbAddPattern.trim() || addingNeverBaseline}
                                        className="flex items-center gap-1.5 px-4 py-2 bg-orange-500/10 hover:bg-orange-500/20 border border-orange-500/20 hover:border-orange-500/40 text-orange-300 rounded-xl text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                    >
                                        {addingNeverBaseline ? <Loader2 className="w-4 h-4 animate-spin" /> : <Ban className="w-4 h-4" />}
                                        Add Rule
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Rules table */}
                        {neverBaselineLoading ? (
                            <div className="flex items-center justify-center py-12 text-gray-400 gap-2">
                                <Loader2 className="w-5 h-5 animate-spin" />
                                <span>Loading...</span>
                            </div>
                        ) : neverBaselines.filter(e => e.source === 'user').length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-12 text-gray-500 gap-2">
                                <Ban className="w-10 h-10 text-gray-700" />
                                <p className="text-sm text-gray-500">No custom rules yet. Add a rule above to permanently block a pattern from being baselined.</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead>
                                        <tr className="border-b border-white/10 bg-white/[0.01]">
                                            <th className="text-left text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider">Signal Type</th>
                                            <th className="text-left text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider">Pattern</th>
                                            <th className="text-left text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider">Description</th>
                                            <th className="text-right text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider">Added</th>
                                            <th className="text-right text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider w-20">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/[0.04]">
                                        {neverBaselines.filter(e => e.source === 'user').map(entry => (
                                            <tr key={entry.id} className="hover:bg-white/[0.03] transition-colors group">
                                                <td className="px-6 py-3">
                                                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-orange-500/10 border border-orange-500/20 text-orange-300">{entry.signal_type}</span>
                                                </td>
                                                <td className="px-6 py-3">
                                                    <code className="text-sm font-mono text-gray-200 bg-white/[0.04] px-2 py-0.5 rounded break-all">{entry.pattern}</code>
                                                </td>
                                                <td className="px-6 py-3 text-sm text-gray-400">{entry.description || <span className="text-gray-600 italic">—</span>}</td>
                                                <td className="px-6 py-3 text-right text-xs text-gray-500">{entry.created_at ? entry.created_at.slice(0, 10) : '—'}</td>
                                                <td className="px-6 py-3 text-right">
                                                    <button
                                                        onClick={() => setDeleteNeverBaselineTarget(entry.id)}
                                                        className="p-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-xl transition-all opacity-0 group-hover:opacity-100"
                                                        title="Remove rule"
                                                    >
                                                        <Trash2 className="w-3.5 h-3.5" />
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </GlassCard>
                </motion.div>
            )}

            {activeTab === 'block-rules' && (
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3 }}
                    className="space-y-6"
                >
                    <GlassCard className="overflow-hidden border-t-4 border-t-red-500/40">
                        <div className="p-5 border-b border-white/5 bg-white/[0.02]">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                                        <ShieldOff className="w-4 h-4 text-red-400" />
                                        Block Rules
                                    </h3>
                                    <p className="text-xs text-gray-400 mt-1">Active block rules will terminate matching processes or drop matching network connections in real-time. Rules with kill_tree enabled will also terminate child processes.</p>
                                </div>
                            </div>
                        </div>

                        {/* Add form */}
                        <div className="px-5 py-4 border-b border-white/[0.06] bg-white/[0.01]">
                            <h4 className="text-sm font-medium text-red-400 mb-3 flex items-center gap-2">
                                <ShieldOff className="w-4 h-4" /> Add Block Rule
                            </h4>
                            <div className="flex flex-col gap-3">
                                <div className="flex gap-2 flex-wrap">
                                    {[
                                        { value: 'process_exec', label: 'Process Exec' },
                                        { value: 'net_connect', label: 'Net Connect' },
                                        { value: 'file_open', label: 'File Open' },
                                    ].map(opt => (
                                        <button key={opt.value} onClick={() => setBrAddSignalType(opt.value)}
                                            className={`px-2.5 py-1 rounded-lg text-xs font-semibold border transition-all ${brAddSignalType === opt.value ? 'bg-red-500/20 border-red-500/40 text-red-300' : 'bg-white/[0.04] border-white/[0.08] text-gray-400 hover:text-gray-200'}`}>
                                            {opt.label}
                                        </button>
                                    ))}
                                </div>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={brAddPattern}
                                        onChange={e => setBrAddPattern(e.target.value)}
                                        onKeyDown={e => { if (e.key === 'Enter') handleAddBlockRule(); }}
                                        placeholder={brAddSignalType === 'process_exec' ? '/usr/bin/ncat or **/mimikatz*' : brAddSignalType === 'net_connect' ? '1.2.3.4:4444 or *:4444' : '/etc/shadow or /tmp/**'}
                                        className="flex-1 min-w-0 bg-white/[0.04] border border-white/[0.10] rounded-xl px-3 py-2 text-sm font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-500/40 focus:bg-white/[0.06]"
                                    />
                                    <input
                                        type="text"
                                        value={brAddDescription}
                                        onChange={e => setBrAddDescription(e.target.value)}
                                        placeholder="Description (optional)"
                                        className="w-56 bg-white/[0.04] border border-white/[0.10] rounded-xl px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-500/40 focus:bg-white/[0.06]"
                                    />
                                    <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer select-none px-2">
                                        <input
                                            type="checkbox"
                                            checked={brAddKillTree}
                                            onChange={e => setBrAddKillTree(e.target.checked)}
                                            className="rounded border-white/20 bg-white/5 text-red-500 focus:ring-red-500/30"
                                        />
                                        Kill Tree
                                    </label>
                                    <button
                                        onClick={handleAddBlockRule}
                                        disabled={!brAddPattern.trim() || addingBlockRule}
                                        className="flex items-center gap-1.5 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 hover:border-red-500/40 text-red-300 rounded-xl text-sm font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                    >
                                        {addingBlockRule ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldOff className="w-4 h-4" />}
                                        Add Rule
                                    </button>
                                </div>
                            </div>
                        </div>

                        {/* Rules table */}
                        {blockRulesLoading ? (
                            <div className="flex items-center justify-center py-12 text-gray-400 gap-2">
                                <Loader2 className="w-5 h-5 animate-spin" />
                                <span>Loading...</span>
                            </div>
                        ) : blockRules.length === 0 ? (
                            <div className="flex flex-col items-center justify-center py-12 text-gray-500 gap-2">
                                <ShieldOff className="w-10 h-10 text-gray-700" />
                                <p className="text-sm text-gray-500">No block rules yet. Add a rule above to actively block matching activity.</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <div className="border border-white/10 rounded-xl overflow-hidden">
                                    <table className="w-full text-xs">
                                        <thead>
                                            <tr className="bg-white/[0.03] border-b border-white/10">
                                                <th className="text-left text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider">Pattern</th>
                                                <th className="text-left text-xs text-gray-400 font-medium px-4 py-3 uppercase tracking-wider">Type</th>
                                                <th className="text-center text-xs text-gray-400 font-medium px-4 py-3 uppercase tracking-wider">Enabled</th>
                                                <th className="text-center text-xs text-gray-400 font-medium px-4 py-3 uppercase tracking-wider">Kill Tree</th>
                                                <th className="text-left text-xs text-gray-400 font-medium px-4 py-3 uppercase tracking-wider">Source</th>
                                                <th className="text-right text-xs text-gray-400 font-medium px-4 py-3 uppercase tracking-wider">Created</th>
                                                <th className="text-right text-xs text-gray-400 font-medium px-6 py-3 uppercase tracking-wider w-20">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/[0.04]">
                                            {blockRules.map(rule => (
                                                <tr key={rule.id} className="hover:bg-white/[0.03] transition-colors group">
                                                    <td className="px-6 py-3">
                                                        <div>
                                                            <code className="text-sm font-mono text-gray-200 bg-white/[0.04] px-2 py-0.5 rounded break-all">{rule.pattern}</code>
                                                            {rule.description && <p className="text-[10px] text-gray-500 mt-1">{rule.description}</p>}
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className="px-2 py-0.5 rounded text-xs font-mono bg-red-500/10 border border-red-500/20 text-red-300">{rule.signal_type}</span>
                                                    </td>
                                                    <td className="px-4 py-3 text-center">
                                                        <button
                                                            onClick={() => handleToggleBlockRule(rule.id, !rule.enabled)}
                                                            disabled={rule.source === 'system'}
                                                            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors duration-200 ${rule.enabled ? 'bg-red-500/60' : 'bg-white/10'} ${rule.source === 'system' ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'}`}
                                                        >
                                                            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow-sm transition-transform duration-200 ${rule.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                                                        </button>
                                                    </td>
                                                    <td className="px-4 py-3 text-center">
                                                        {rule.kill_tree ? (
                                                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/25">kill tree</span>
                                                        ) : (
                                                            <span className="text-[10px] text-gray-600">—</span>
                                                        )}
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${rule.source === 'system' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'}`}>
                                                            {rule.source}
                                                        </span>
                                                    </td>
                                                    <td className="px-4 py-3 text-right text-xs text-gray-500">{rule.created_at ? rule.created_at.slice(0, 10) : '—'}</td>
                                                    <td className="px-6 py-3 text-right">
                                                        <button
                                                            onClick={() => setDeleteBlockRuleTarget(rule.id)}
                                                            disabled={rule.source === 'system'}
                                                            className={`p-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-xl transition-all ${rule.source === 'system' ? 'opacity-30 cursor-not-allowed' : 'opacity-0 group-hover:opacity-100'}`}
                                                            title={rule.source === 'system' ? 'System rules cannot be deleted' : 'Remove rule'}
                                                        >
                                                            <Trash2 className="w-3.5 h-3.5" />
                                                        </button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </GlassCard>
                </motion.div>
            )}

            {activeTab === 'auto-suppressed' && (
                <div className="space-y-4">
                    {/* Sub-tab toggle */}
                    <div className="flex gap-1 bg-white/[0.03] rounded-lg p-1 w-fit">
                        {([['baselines', 'Baseline Matches'], ['command-noise', 'Command Noise']] as const).map(([key, label]) => (
                            <button
                                key={key}
                                onClick={() => setSuppressedSubTab(key)}
                                className={`px-4 py-1.5 rounded-md text-xs font-medium transition-all ${suppressedSubTab === key ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                            >
                                {label}
                            </button>
                        ))}
                    </div>

                    {suppressedSubTab === 'baselines' && (
                        <>
                            <div className="border border-white/10 rounded-xl p-4 bg-white/[0.02]">
                                <div className="flex items-center gap-2 mb-1">
                                    <Eye className="w-4 h-4 text-cyan-400" />
                                    <h3 className="text-sm font-medium text-cyan-400">Auto-Suppressed Findings</h3>
                                </div>
                                <p className="text-xs text-gray-500">
                                    These findings were automatically suppressed because they match learned behavioral baselines.
                                    They still appear under Resolved in the Findings page.
                                </p>
                            </div>

                            {suppressedLoading ? (
                                <div className="text-center py-8 text-gray-500 text-sm">Loading suppressed findings...</div>
                            ) : suppressedGroups.length === 0 ? (
                                <div className="text-center py-8 text-gray-500 text-sm">No suppressed findings in the last 24 hours</div>
                            ) : (
                                <div className="border border-white/10 rounded-xl overflow-hidden">
                                    <table className="w-full text-xs">
                                        <thead>
                                            <tr className="bg-white/[0.03] border-b border-white/10">
                                                <th className="text-left px-4 py-2.5 text-gray-400 font-medium">Suppression Reason</th>
                                                <th className="text-right px-4 py-2.5 text-gray-400 font-medium w-24">Count</th>
                                                <th className="text-right px-4 py-2.5 text-gray-400 font-medium w-40">Last Seen</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {suppressedGroups.map((g, i) => (
                                                <tr key={i} className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                                                    <td className="px-4 py-2.5">
                                                        <span className="text-gray-300 font-mono text-[11px]">{g.baseline_match || 'Unknown pattern'}</span>
                                                    </td>
                                                    <td className="px-4 py-2.5 text-right">
                                                        <span className="text-cyan-400 font-mono tabular-nums">{g.count.toLocaleString()}</span>
                                                    </td>
                                                    <td className="px-4 py-2.5 text-right text-gray-500">
                                                        {new Date(g.last_seen).toLocaleString()}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                    <div className="px-4 py-2 bg-white/[0.02] border-t border-white/10 text-[10px] text-gray-500">
                                        Total: {suppressedGroups.reduce((sum, g) => sum + g.count, 0).toLocaleString()} suppressed findings across {suppressedGroups.length} patterns (last 24h)
                                    </div>
                                </div>
                            )}
                        </>
                    )}

                    {suppressedSubTab === 'command-noise' && (
                        <>
                            <div className="border border-white/10 rounded-xl p-4 bg-white/[0.02]">
                                <div className="flex items-center gap-2 mb-1">
                                    <Terminal className="w-4 h-4 text-orange-400" />
                                    <h3 className="text-sm font-medium text-orange-400">Command Noise Filters</h3>
                                </div>
                                <p className="text-xs text-gray-500">
                                    These binaries are automatically filtered from findings. Windows system processes and
                                    bare runtimes without arguments produce no security signal and are suppressed at the detection level.
                                </p>
                            </div>

                            {noiseLoading ? (
                                <div className="text-center py-8 text-gray-500 text-sm">Loading noise filters...</div>
                            ) : !noiseFilters ? (
                                <div className="text-center py-8 text-gray-500 text-sm">Failed to load noise filters</div>
                            ) : (
                                <div className="space-y-3">
                                    {([
                                        { key: 'system_noise' as const, title: 'System Noise', desc: 'Windows system processes spawned automatically (conhost, csrss, etc.). Always filtered — no security value.', color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
                                        { key: 'build_noise' as const, title: 'Build Tools', desc: 'Compiler/linker internals spawned during builds. The build command itself is tracked separately.', color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
                                        { key: 'always_noise' as const, title: 'Runtime Noise', desc: 'Internal runtime artifacts (ldconfig, locale, tput, etc.). Always filtered regardless of arguments.', color: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/20' },
                                        { key: 'bare_noise' as const, title: 'Bare Runtimes (no args only)', desc: 'These binaries are only suppressed when run without arguments. With arguments (e.g. reg query HKLM\\...), they generate findings normally.', color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20' },
                                    ]).map(({ key, title, desc, color, bg, border }) => (
                                        <div key={key} className={`border ${border} rounded-xl overflow-hidden`}>
                                            <div className={`px-4 py-2.5 ${bg}`}>
                                                <h4 className={`text-xs font-semibold ${color}`}>{title}</h4>
                                                <p className="text-[10px] text-gray-500 mt-0.5">{desc}</p>
                                            </div>
                                            <div className="px-4 py-3 flex flex-wrap gap-1.5">
                                                {(noiseFilters[key] || []).sort().map((name) => (
                                                    <span key={name} className="px-2 py-0.5 bg-white/[0.04] border border-white/10 rounded text-[11px] font-mono text-gray-300">
                                                        {name}
                                                    </span>
                                                ))}
                                                {(!noiseFilters[key] || noiseFilters[key].length === 0) && (
                                                    <span className="text-[11px] text-gray-600">No filters configured</span>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </>
                    )}
                </div>
            )}

            <ConfirmDialog
                open={deleteExclusionTarget !== null}
                onConfirm={() => {
                    if (deleteExclusionTarget !== null) {
                        handleDeleteExclusion(deleteExclusionTarget);
                    }
                    setDeleteExclusionTarget(null);
                }}
                onCancel={() => setDeleteExclusionTarget(null)}
                title="Re-enable Auto-Learning"
                description="This will remove the exclusion, allowing the system to auto-learn this pattern again from clean events. The baseline will be recreated automatically once the pattern is observed."
                confirmLabel="Re-enable"
                confirmVariant="success"
            />

            <ConfirmDialog
                open={suspendTarget !== null}
                onConfirm={() => {
                    if (suspendTarget !== null) {
                        handleSuspendBaseline(suspendTarget, suspendDuration);
                    }
                    setSuspendTarget(null);
                    setSuspendDuration('7d');
                }}
                onCancel={() => { setSuspendTarget(null); setSuspendDuration('7d'); }}
                title="Suspend Baseline"
                description="This baseline will be temporarily disabled. The detection engine will start flagging this behavior until the suspension expires."
                confirmLabel="Suspend"
                confirmVariant="danger"
            >
                <div className="mt-3">
                    <label className="text-xs text-white/50 mb-1.5 block">Suspend for</label>
                    <div className="flex gap-1.5">
                        {[
                            { value: '7d', label: '7 days' },
                            { value: '30d', label: '30 days' },
                            { value: '90d', label: '90 days' },
                        ].map(opt => (
                            <button
                                key={opt.value}
                                onClick={() => setSuspendDuration(opt.value)}
                                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 border ${
                                    suspendDuration === opt.value
                                        ? 'bg-amber-500/20 border-amber-500/40 text-amber-400'
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
                open={deleteTarget !== null}
                onConfirm={() => {
                    if (deleteTarget !== null) {
                        handleDeleteBaseline(deleteTarget);
                    }
                    setDeleteTarget(null);
                }}
                onCancel={() => setDeleteTarget(null)}
                title="Remove Baseline"
                description="This baseline pattern will be removed and an exclusion will be created to prevent it from being auto-learned again. The detection engine will start flagging this behavior."
                confirmLabel="Remove"
                confirmVariant="danger"
            />

            <ConfirmDialog
                open={confirmTarget !== null}
                onConfirm={() => {
                    if (confirmTarget !== null) {
                        handleConfirmBaseline(confirmTarget);
                    }
                    setConfirmTarget(null);
                }}
                onCancel={() => setConfirmTarget(null)}
                title="Allow Always"
                description="This will permanently confirm this baseline. It will no longer expire and the detection engine will always suppress alerts matching this pattern."
                confirmLabel="Allow Always"
                confirmVariant="success"
            />

            <ConfirmDialog
                open={addDirTarget !== null}
                onConfirm={handleAddDirBaseline}
                onCancel={() => setAddDirTarget(null)}
                title="Allow Directory"
                description={`This will baseline all file accesses under ${addDirTarget?.path || ''} for the selected agent. The detection engine will suppress alerts for files in this directory.`}
                confirmLabel={addingDir ? 'Adding...' : 'Allow Directory'}
                confirmVariant="success"
            >
                <div className="mt-3">
                    <label className="text-xs text-white/50 mb-1.5 block">AI Agent</label>
                    <div className="flex gap-1.5 flex-wrap">
                        {Object.entries(AI_AGENT_NAMES).map(([key, label]) => (
                            <button
                                key={key}
                                onClick={() => setAddDirAiType(key)}
                                className={`px-2.5 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 border flex items-center gap-1.5 ${
                                    addDirAiType === key
                                        ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                                        : 'bg-white/5 border-white/10 text-white/50 hover:text-white/70 hover:bg-white/10'
                                }`}
                            >
                                <Bot className="w-3 h-3" />
                                {label}
                            </button>
                        ))}
                    </div>
                </div>
            </ConfirmDialog>

            <ConfirmDialog
                open={deleteDomainTarget !== null}
                onConfirm={() => {
                    if (deleteDomainTarget !== null) {
                        handleDeleteDomain(deleteDomainTarget);
                    }
                    setDeleteDomainTarget(null);
                }}
                onCancel={() => setDeleteDomainTarget(null)}
                title="Remove Safe Domain"
                description="Removing this domain will cause the detection engine to start flagging connections to it as suspicious. This action cannot be undone."
                confirmLabel="Remove"
                confirmVariant="danger"
            />

            {/* Never-baseline: delete org rule */}
            <ConfirmDialog
                open={deleteNeverBaselineTarget !== null}
                onConfirm={() => {
                    if (deleteNeverBaselineTarget !== null) handleDeleteNeverBaseline(deleteNeverBaselineTarget);
                    setDeleteNeverBaselineTarget(null);
                }}
                onCancel={() => setDeleteNeverBaselineTarget(null)}
                title="Remove Never-Baseline Rule"
                description="Removing this rule allows the learning engine to baseline this pattern again in the future. The detection engine will no longer guarantee an incident for this pattern."
                confirmLabel="Remove"
                confirmVariant="danger"
            />

            {/* Never-baseline: conflict — existing baselines match */}
            <ConfirmDialog
                open={nbConflictDialog !== null}
                onConfirm={handleNeverBaselineConflictConfirm}
                onCancel={() => { setNbConflictDialog(null); setNbConflictPending(null); }}
                title="Existing Baselines Conflict"
                description={nbConflictDialog ? `${nbConflictDialog.baseline_ids.length} existing baseline${nbConflictDialog.baseline_ids.length !== 1 ? 's' : ''} match this pattern. They must be removed before this rule can be added. Remove them now and proceed?` : ''}
                confirmLabel="Remove Baselines & Add Rule"
                confirmVariant="danger"
            />

            {/* Never-baseline: user-defined block on createBaseline */}
            <ConfirmDialog
                open={nbIsUserDefinedBlock !== null}
                onConfirm={() => { setNbIsUserDefinedBlock(null); setActiveTab('never-baseline'); }}
                onCancel={() => setNbIsUserDefinedBlock(null)}
                title="Blocked by Never-Baseline Rule"
                description={nbIsUserDefinedBlock || ''}
                confirmLabel="Go to Never-Baseline tab"
                confirmVariant="danger"
            />

            {/* Block rules: delete rule */}
            <ConfirmDialog
                open={deleteBlockRuleTarget !== null}
                onConfirm={() => {
                    if (deleteBlockRuleTarget !== null) handleDeleteBlockRule(deleteBlockRuleTarget);
                    setDeleteBlockRuleTarget(null);
                }}
                onCancel={() => setDeleteBlockRuleTarget(null)}
                title="Remove Block Rule"
                description="Removing this block rule will stop the system from actively blocking matching activity. The pattern will no longer be terminated or dropped."
                confirmLabel="Remove"
                confirmVariant="danger"
            />

            {/* Toasts */}
            <AnimatePresence>
                {toastSuccess && (
                    <motion.div
                        initial={{ opacity: 0, y: 40 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 40 }}
                        className="fixed bottom-6 right-6 z-50 max-w-md px-4 py-3 bg-green-500/15 border border-green-500/30 rounded-xl backdrop-blur-md shadow-lg shadow-black/30 flex items-start gap-3"
                    >
                        <div className="shrink-0 w-5 h-5 rounded-full bg-green-500/20 flex items-center justify-center mt-0.5">
                            <ShieldCheck className="w-3 h-3 text-green-400" />
                        </div>
                        <p className="text-sm text-green-300 flex-1">{toastSuccess}</p>
                        <button onClick={() => setToastSuccess(null)} className="shrink-0 text-green-400/60 hover:text-green-300 transition-colors">
                            <X className="w-4 h-4" />
                        </button>
                    </motion.div>
                )}
                {toastError && (
                    <motion.div
                        initial={{ opacity: 0, y: 40 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 40 }}
                        className="fixed bottom-6 right-6 z-50 max-w-md px-4 py-3 bg-red-500/15 border border-red-500/30 rounded-xl backdrop-blur-md shadow-lg shadow-black/30 flex items-start gap-3"
                    >
                        <div className="shrink-0 w-5 h-5 rounded-full bg-red-500/20 flex items-center justify-center mt-0.5">
                            <X className="w-3 h-3 text-red-400" />
                        </div>
                        <p className="text-sm text-red-300 flex-1">{toastError}</p>
                        <button onClick={() => setToastError(null)} className="shrink-0 text-red-400/60 hover:text-red-300 transition-colors">
                            <X className="w-4 h-4" />
                        </button>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

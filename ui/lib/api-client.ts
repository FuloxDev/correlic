import { fetchJSON } from './api'

// AI agent display names — maps raw ai_type from backend to user-friendly labels
export const AI_AGENT_NAMES: Record<string, string> = {
    claude: 'Claude Code',
    cursor: 'Cursor',
    copilot: 'GitHub Copilot',
    aider: 'Aider',
    cody: 'Sourcegraph Cody',
    continue: 'Continue',
    codeium: 'Codeium',
    langchain: 'LangChain',
    autogpt: 'AutoGPT',
    crewai: 'CrewAI',
    openinterpreter: 'Open Interpreter',
    moltbot: 'OpenClaw',
}

export function aiAgentDisplayName(aiType: string): string {
    if (!aiType) return 'Unknown AI Agent'
    return AI_AGENT_NAMES[aiType.toLowerCase()] || aiType
}

// AI-specific metrics
export interface AIStats {
    total_agents: number
    total_events: number
    active_alerts: number
    connections: number
    secrets_accessed: number
    ports_accessed: number
}

// Dashboard stats
export interface DetectionStats {
    total_findings: number
    pending_findings: number
    allowed_findings: number
    dismissed_findings: number
    auto_resolved_findings: number
    investigating_findings: number
    suppressed_findings: number
    total_baselines: number
    auto_baselines: number
    manual_baselines: number
    suppression_rate: number
}

export interface IncidentSummaryStats {
    total: number
    open: number
    investigating: number
    resolved: number
    dismissed: number
    auto_resolved: number
    critical_open: number
}

export interface EventBreakdown {
    process_exec: number
    file_open: number
    net_connect: number
    net_dns: number
    process_exit: number
}

export interface DashboardStats {
    // System-wide metrics
    total_events: number
    total_alerts: number
    critical_alerts: number
    high_risk_alerts: number
    open_ports: number
    active_connections: number
    secrets_accessed: number
    // AI-specific metrics
    ai: AIStats
    // Detection engine metrics
    detection: DetectionStats
    // Incident metrics
    incidents: IncidentSummaryStats
    // Event type breakdown
    events: EventBreakdown
}

export async function getDashboardStats(intervalMinutes?: number): Promise<DashboardStats> {
    const query = intervalMinutes ? `?interval=${intervalMinutes}` : ''
    return fetchJSON<DashboardStats>(`/dashboard/stats${query}`)
}

// Dashboard trends (time-series for charts/sparklines)
export interface TrendPoint {
    timestamp: string
    events: number
    findings: number
    incidents: number
    agent_findings?: Record<string, number>
    finding_severities?: Record<string, number>
    finding_rules?: Record<string, number>
    incident_severities?: Record<string, number>
}

export interface TrendsResponse {
    points: TrendPoint[]
    bucket_minutes: number
}

export async function getDashboardTrends(points = 12, intervalMinutes = 5): Promise<TrendsResponse> {
    return fetchJSON<TrendsResponse>(`/dashboard/trends?points=${points}&interval=${intervalMinutes}`)
}

// Telemetry events
export interface TelemetryEvent {
    id: string
    org_id: string
    agent_id: string
    event_type: string
    payload: Record<string, unknown>
    timestamp: string
    created_at: string
}

export interface TelemetryListParams {
    event_type?: string
    agent_id?: string
    since?: string
    until?: string
    limit?: number
    offset?: number
    ai_only?: boolean
}

export async function getEvents(params: TelemetryListParams = {}): Promise<TelemetryEvent[]> {
    const query = new URLSearchParams()
    if (params.event_type) query.set('event_type', params.event_type)
    if (params.agent_id) query.set('agent_id', params.agent_id)
    if (params.since) query.set('since', params.since)
    if (params.until) query.set('until', params.until)
    if (params.limit) query.set('limit', String(params.limit))
    if (params.offset) query.set('offset', String(params.offset))
    if (params.ai_only) query.set('ai_only', 'true')

    const queryStr = query.toString()
    return fetchJSON<TelemetryEvent[]>(`/telemetry${queryStr ? '?' + queryStr : ''}`)
}

// Agents
export interface Agent {
    id: string
    name: string
    org_id: string
    status: 'active' | 'inactive' | 'offline'
    last_seen?: string
    created_at: string
}

export async function getAgents(): Promise<Agent[]> {
    return fetchJSON<Agent[]>('/agents')
}

// Ports summary
export interface PortService {
    key: string
    port: number
    comm: string
    pcomm?: string
    addresses: string[]
    instances?: { pid: number; uid?: number }[]
    risk: string
    exposed: boolean
    is_ai: boolean
    ai_type?: string
}

export interface PortsSummaryResponse {
    window: { since: string; until: string }
    counts: { open_services: number; exposed: number }
    services: PortService[]
}

export async function getPortsSummary(since?: string, until?: string): Promise<PortsSummaryResponse> {
    const params = new URLSearchParams()
    if (since) params.set('since', since)
    if (until) params.set('until', until)
    const queryStr = params.toString()
    return fetchJSON<PortsSummaryResponse>(`/ports/summary${queryStr ? '?' + queryStr : ''}`)
}

// AI Settings
export interface LLMProvider {
    provider: string
    model: string
    enabled: boolean
    created_at: string
    updated_at: string
}

export async function getLLMSettings(): Promise<LLMProvider[]> {
    const resp = await fetchJSON<{ settings: LLMProvider[]; available_providers: unknown[] }>('/api/v1/ai/settings')
    return resp.settings ?? []
}

export interface SaveLLMSettingsRequest {
    provider: string
    api_key: string
    model?: string
}

export async function saveLLMSettings(data: SaveLLMSettingsRequest): Promise<LLMProvider> {
    return fetchJSON<LLMProvider>('/api/v1/ai/settings', {
        method: 'POST',
        body: JSON.stringify(data),
    })
}

export async function switchLLMProvider(provider: string): Promise<void> {
    await fetchJSON('/api/v1/ai/settings/switch', {
        method: 'PUT',
        body: JSON.stringify({ provider }),
    })
}

// API Keys
export interface APIKey {
    id: string
    name: string
    key_prefix: string
    created_at: string
    last_used?: string
}

export async function getAPIKeys(): Promise<APIKey[]> {
    const resp = await fetchJSON<APIKey[] | null>('/api-keys')
    return resp ?? []
}

export async function createAPIKey(name: string): Promise<{ id: string; key: string }> {
    return fetchJSON<{ id: string; key: string }>('/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name }),
    })
}

export async function deleteAPIKey(id: string): Promise<void> {
    await fetchJSON(`/api-keys?id=${id}`, {
        method: 'DELETE',
    })
}

// AI Agent Patterns
export interface AIAgentPattern {
    id: number
    pattern: string
    agent_type: string
    description: string
    created_at: string
}

export async function getAgentPatterns(): Promise<AIAgentPattern[]> {
    const resp = await fetchJSON<{ patterns: AIAgentPattern[] }>('/api/v1/ai/agent-patterns')
    return resp.patterns || []
}

export async function createAgentPattern(data: { pattern: string; agent_type: string; description?: string }): Promise<AIAgentPattern> {
    const resp = await fetchJSON<{ pattern: AIAgentPattern }>('/api/v1/ai/agent-patterns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    })
    return resp.pattern
}

export async function deleteAgentPattern(id: number): Promise<void> {
    await fetchJSON(`/api/v1/ai/agent-patterns/${id}`, { method: 'DELETE' })
}

export async function suggestAIPatterns(softwareName: string): Promise<{ suggestion: string; model: string }> {
    return fetchJSON('/api/v1/ai/suggest-patterns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software_name: softwareName }),
    })
}

// Process Timeline (Interactive View)
export interface ProcessStats {
    files_accessed: number
    connections: number
    secrets_accessed: number
    ports_opened: number
    child_count: number
    event_count: number
}

export interface ProcessNode {
    pid: number
    ppid: number
    comm: string
    exe_path: string
    cmdline?: string
    user?: string
    host_id: string
    started_at: string
    last_seen_at: string
    duration_ms: number
    ai_type?: string
    stats: ProcessStats
    children?: ProcessNode[]
}

export interface ProcessTreeResponse {
    processes: ProcessNode[]
    total_count: number
    window_start: string
    window_end: string
}

export async function getProcessTree(intervalMinutes: number = 60): Promise<ProcessTreeResponse> {
    return fetchJSON<ProcessTreeResponse>(`/processes/tree?interval=${intervalMinutes}`)
}

// Network Events with destination details
export interface NetworkEvent {
    id: string
    timestamp: string
    type: string
    target_ip: string
    target_port: number
    protocol?: string
    category?: string
}

export interface ProcessActivityResponse {
    pid: number
    host_id: string
    network_events: NetworkEvent[]
    total_connections: number
}

export async function getProcessNetworkEvents(pid: number, hostId: string, limit: number = 50): Promise<ProcessActivityResponse> {
    return fetchJSON<ProcessActivityResponse>(`/processes/activity?pid=${pid}&host_id=${hostId}&limit=${limit}`)
}


export interface NetworkSummary {
    ports: { port: number; ip: string; count: number }[];
    connections: { remote_ip: string; remote_port: number; count: number; is_external: boolean; domain?: string }[];
    files: { path: string; count: number }[];
    dns: { domain: string; count: number }[];
}

export async function getNetworkSummary(pids: number[], hostId: string): Promise<NetworkSummary> {
    return fetchJSON<NetworkSummary>('/processes/summary', {
        method: 'POST',
        body: JSON.stringify({ pids, host_id: hostId }),
    })
}

// Helper to get a display name for a process
export function getProcessName(node: ProcessNode): string {
    if (node.ai_type) return node.ai_type;
    return node.comm || node.exe_path?.split('/').pop() || `PID ${node.pid}`;
}

// Agent Activity Stream
export interface AgentAction {
    timestamp: string
    category: string      // "file", "network", "command", "dns"
    action: string         // human-readable: "📝 Edited timeline.go"
    detail: string         // raw path/IP/command
    significance: number   // 1-5
    event_id: string
    event_type: string
    process_pid?: number
    process_comm?: string
}

export interface AgentStats {
    files_modified: number
    files_read: number
    commands_run: number
    connections: number
    dns_lookups: number
    total_events: number
}

export interface AgentSummary {
    agent_name: string
    agent_pid: number
    ai_type: string
    host_id: string
    exe_path?: string
    started_at: string
    duration: string
    actions: AgentAction[]
    stats: AgentStats
    child_count: number
}

export interface AgentActivityResponse {
    agents: AgentSummary[]
    window_start: string
    window_end: string
}

export async function getAgentActivity(intervalMinutes: number = 30, minSignificance: number = 2): Promise<AgentActivityResponse> {
    return fetchJSON<AgentActivityResponse>(`/agents/activity?interval=${intervalMinutes}&min_significance=${minSignificance}`)
}

// Detection Findings
export interface Finding {
    id: string
    detection_id: string
    host_id: string
    severity: string
    confidence: number
    title: string
    summary: string
    anchor_event: string
    related_events: string[]
    context: Record<string, unknown>
    status: string
    resolution?: string
    resolved_by?: string
    resolved_at?: string
    suppressed: boolean
    baseline_match?: string
    incident_id?: string
    created_at: string
}

export async function getFindings(params: { host_id?: string; status?: string; limit?: number } = {}): Promise<Finding[]> {
    const query = new URLSearchParams()
    if (params.host_id) query.set('host_id', params.host_id)
    if (params.status) query.set('status', params.status)
    if (params.limit) query.set('limit', String(params.limit))
    const queryStr = query.toString()
    const resp = await fetchJSON<{ findings: Finding[] }>(`/api/v1/findings${queryStr ? '?' + queryStr : ''}`)
    return resp.findings
}

export interface FindingsResponse {
    findings: Finding[]
    count: number
    total: number
    total_pending: number
}

export async function getFindingsWithTotals(params: { host_id?: string; status?: string; limit?: number; since?: string } = {}): Promise<FindingsResponse> {
    const query = new URLSearchParams()
    if (params.host_id) query.set('host_id', params.host_id)
    if (params.status) query.set('status', params.status)
    if (params.limit) query.set('limit', String(params.limit))
    if (params.since) query.set('since', params.since)
    const queryStr = query.toString()
    return fetchJSON<FindingsResponse>(`/api/v1/findings${queryStr ? '?' + queryStr : ''}`)
}

export async function getFinding(id: string): Promise<Finding> {
    return fetchJSON<Finding>(`/api/v1/findings/${encodeURIComponent(id)}`)
}

export async function resolveFinding(id: string, status: string, resolution: string, options?: { baseline_mode?: string }): Promise<void> {
    await fetchJSON(`/api/v1/findings/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, resolution, ...options }),
    })
}

export async function reconcileFindings(): Promise<{ reconciled: number }> {
    return fetchJSON<{ reconciled: number }>('/api/v1/findings/reconcile', { method: 'POST' })
}

export interface DomainResolution {
    finding_id: string
    ip: string
    domains: string[]
    source: string
    asn_name: string
    asn: string
    bgp_prefix: string
    reverse_dns: string
}

export async function resolveFindingDomain(id: string): Promise<DomainResolution> {
    return fetchJSON<DomainResolution>(`/api/v1/findings/${encodeURIComponent(id)}/resolve-domain`, {
        method: 'POST',
    })
}

// IP Enrichment (reverse DNS, ASN, BGP)
export interface IPEnrichment {
    ip: string
    domain: string
    source: string
    asn_name: string
    asn: string
    bgp_prefix: string
    reverse_dns: string
}

export async function resolveIP(ip: string): Promise<IPEnrichment> {
    return fetchJSON<IPEnrichment>('/api/v1/enrich/ip', {
        method: 'POST',
        body: JSON.stringify({ ip }),
    })
}

export async function resolveBulkIPs(ips: string[]): Promise<{ results: IPEnrichment[] }> {
    return fetchJSON<{ results: IPEnrichment[] }>('/api/v1/enrich/ips', {
        method: 'POST',
        body: JSON.stringify({ ips }),
    })
}

// Rule Exceptions
export async function createException(data: {
    detection_id: string
    host_id?: string
    context_key: string
    context_value: string
    match_mode?: 'exact' | 'prefix'
    reason: string
}): Promise<{ id: number }> {
    return fetchJSON<{ id: number }>('/api/v1/exceptions', {
        method: 'POST',
        body: JSON.stringify({
            ...data,
            host_id: data.host_id || '*',
            match_mode: data.match_mode || 'exact',
        }),
    })
}

// Behavioral Baselines
export interface Baseline {
    id: number
    host_id: string
    ai_type: string
    signal_type: string
    pattern: string
    source: string
    hit_count: number
    first_seen: string
    last_seen: string
    expires_at?: string // ISO 8601 "allowed until"; null = permanent
    suspended_until?: string // ISO 8601 "paused until"; null = active
}

export async function getBaselines(params: { host_id?: string; signal_type?: string; limit?: number; offset?: number } = {}): Promise<{ baselines: Baseline[]; has_more: boolean }> {
    const q = new URLSearchParams()
    if (params.host_id) q.set('host_id', params.host_id)
    if (params.signal_type) q.set('signal_type', params.signal_type)
    if (params.limit) q.set('limit', String(params.limit))
    if (params.offset) q.set('offset', String(params.offset))

    return fetchJSON<{ baselines: Baseline[]; has_more: boolean }>(`/api/v1/baselines?${q.toString()}`)
        .then(r => ({ baselines: r.baselines || [], has_more: r.has_more ?? false }))
}

export interface BaselineSummaryBucket {
    source: 'auto' | 'manual'
    signal_type: string
    count: number
}

export interface BaselineSummary {
    buckets: BaselineSummaryBucket[]
    auto_total: number
    manual_total: number
    total: number
}

export async function getBaselineSummary(): Promise<BaselineSummary> {
    return fetchJSON<BaselineSummary>('/api/v1/baselines/summary')
}

export interface SafeDomain {
    id: string;
    domain: string;
    description: string;
    created_at: string;
}

export async function deleteBaseline(id: number): Promise<void> {
    await fetchJSON(`/api/v1/baselines/${id}`, { method: 'DELETE' })
}

export async function suspendBaseline(id: number, expiresIn: string): Promise<{ id: number; suspended_until: string }> {
    return fetchJSON<{ id: number; suspended_until: string }>(`/api/v1/baselines/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expires_in: expiresIn }),
    })
}

export async function confirmBaseline(id: number): Promise<void> {
    await fetchJSON(`/api/v1/baselines/${id}/confirm`, { method: 'POST' })
}

export async function createBaseline(params: { signal_type: string; pattern: string; host_id?: string; ai_type?: string }): Promise<{ ok: boolean; retroactive_resolved?: number }> {
    return fetchJSON<{ ok: boolean; retroactive_resolved?: number }>('/api/v1/baselines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
    })
}

export async function getSafeDomains(): Promise<SafeDomain[]> {
    return fetchJSON<{ domains: SafeDomain[] }>('/api/v1/baselines/safe-domains')
        .then(r => r.domains || []);
}

export async function addSafeDomain(domain: string, description: string): Promise<SafeDomain> {
    return fetchJSON<SafeDomain>('/api/v1/baselines/safe-domains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, description }),
    })
}

export async function deleteSafeDomain(id: string): Promise<void> {
    await fetchJSON(`/api/v1/baselines/safe-domains/${id}`, { method: 'DELETE' })
}

// Baseline Exclusions
export interface BaselineExclusion {
    id: number
    org_id: string
    host_id: string
    ai_type: string
    signal_type: string
    pattern: string
    created_by: string
    created_at: string
}

export async function getBaselineExclusions(): Promise<BaselineExclusion[]> {
    return fetchJSON<{ exclusions: BaselineExclusion[] }>('/api/v1/baselines/exclusions')
        .then(r => r.exclusions || [])
}

export async function deleteBaselineExclusion(id: number): Promise<void> {
    await fetchJSON(`/api/v1/baselines/exclusions/${id}`, { method: 'DELETE' })
}

// Never Baselines
export interface NeverBaselineEntry {
    id: number
    signal_type: string
    pattern: string
    category?: string
    description: string
    source: 'system' | 'user'
    created_by?: string
    created_at?: string
}

export async function getNeverBaselines(): Promise<NeverBaselineEntry[]> {
    return fetchJSON<NeverBaselineEntry[]>('/api/v1/baselines/never-baselines')
}

export async function createNeverBaseline(params: {
    signal_type: string
    pattern: string
    description?: string
}): Promise<NeverBaselineEntry> {
    return fetchJSON<NeverBaselineEntry>('/api/v1/baselines/never-baselines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
    })
}

export async function deleteNeverBaseline(id: number): Promise<void> {
    await fetchJSON(`/api/v1/baselines/never-baselines/${id}`, { method: 'DELETE' })
}

// Block Rules
export interface BlockRule {
    id: number
    org_id: string
    signal_type: string
    pattern: string
    description: string
    enabled: boolean
    kill_tree: boolean
    source: string
    created_by: string
    created_at: string
    updated_at: string
}

export interface BlockEventStats {
    total_blocked: number
    success_count: number
    failed_count: number
    unique_rules: number
}

export async function getBlockRules(): Promise<BlockRule[]> {
    return fetchJSON<BlockRule[]>('/api/v1/block-rules')
}

export async function createBlockRule(params: {
    signal_type: string
    pattern: string
    description?: string
    kill_tree?: boolean
}): Promise<BlockRule> {
    return fetchJSON<BlockRule>('/api/v1/block-rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
    })
}

export async function updateBlockRule(id: number, params: {
    enabled?: boolean
    description?: string
    kill_tree?: boolean
}): Promise<void> {
    await fetchJSON(`/api/v1/block-rules/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
    })
}

export async function deleteBlockRule(id: number): Promise<void> {
    await fetchJSON(`/api/v1/block-rules/${id}`, { method: 'DELETE' })
}

export async function getBlockEventStats(): Promise<BlockEventStats> {
    return fetchJSON<BlockEventStats>('/api/v1/block-events/stats')
}

// Suppressed findings summary
export interface SuppressedGroup {
    baseline_match: string
    count: number
    last_seen: string
}

export async function getSuppressedSummary(since?: string): Promise<SuppressedGroup[]> {
    const params = since ? `?since=${encodeURIComponent(since)}` : ''
    return fetchJSON<SuppressedGroup[]>(`/api/v1/findings/suppressed-summary${params}`)
}

export interface NoiseFilters {
    system_noise: string[]
    build_noise: string[]
    always_noise: string[]
    bare_noise: string[]
}

export async function getNoiseFilters(): Promise<NoiseFilters> {
    return fetchJSON<NoiseFilters>('/api/v1/baselines/noise-filters')
}

// Resolve finding with optional baseline duration
export async function resolveFindingWithExpiry(
    id: string, status: string, resolution: string,
    options?: { expires_in?: string; expires_at?: string; baseline_mode?: string }
): Promise<void> {
    await fetchJSON(`/api/v1/findings/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, resolution, ...options }),
    })
}

// Incidents
// Attack category labels and colors for incident badges.
export const CATEGORY_LABELS: Record<string, string> = {
    credential_theft: 'Credential Theft',
    execution: 'Suspicious Execution',
    privilege_escalation: 'Privilege Escalation',
    persistence: 'Persistence',
    exfiltration: 'Data Exfiltration',
    reconnaissance: 'Reconnaissance',
    tampering: 'Code Tampering',
    other: 'Other',
}

export const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string; hex: string }> = {
    credential_theft:     { bg: 'bg-red-500/10',    text: 'text-red-300',    border: 'border-red-500/20',    hex: '#ef4444' },
    execution:            { bg: 'bg-orange-500/10', text: 'text-orange-300', border: 'border-orange-500/20', hex: '#f97316' },
    privilege_escalation: { bg: 'bg-rose-500/10',   text: 'text-rose-300',   border: 'border-rose-500/20',   hex: '#f43f5e' },
    persistence:          { bg: 'bg-purple-500/10', text: 'text-purple-300', border: 'border-purple-500/20', hex: '#a855f7' },
    exfiltration:         { bg: 'bg-cyan-500/10',   text: 'text-cyan-300',   border: 'border-cyan-500/20',   hex: '#06b6d4' },
    reconnaissance:       { bg: 'bg-blue-500/10',   text: 'text-blue-300',   border: 'border-blue-500/20',   hex: '#3b82f6' },
    tampering:            { bg: 'bg-yellow-500/10', text: 'text-yellow-300', border: 'border-yellow-500/20', hex: '#eab308' },
    other:                { bg: 'bg-gray-500/10',   text: 'text-gray-300',   border: 'border-gray-500/20',   hex: '#6b7280' },
}

export interface Incident {
    id: string
    org_id: string
    host_id: string
    category: string
    severity: string
    confidence: number
    title: string
    summary?: string
    mitre_techniques?: string[]
    finding_ids: string[]
    chain_finding_id?: string
    started_at: string
    ended_at: string
    context_summary?: Record<string, unknown>
    status: string
    resolution?: string
    resolved_by?: string
    resolved_at?: string
    created_at: string
    updated_at: string
}

export interface IncidentCounts {
    total: number
    open: number
    investigating: number
    resolved: number
    dismissed: number
    auto_resolved: number
}

export interface FindingSummary {
    id: string
    detection_id: string
    severity: string
    confidence: number
    title: string
    summary: string
    context?: Record<string, unknown>
    timestamp: string
    status: string
}

export interface TimelineEntry {
    timestamp: string
    type: string
    event_type?: string
    title: string
    detail?: string
    severity?: string
    event_id?: string
    finding_id?: string
    pid?: number
    properties?: Record<string, unknown>
}

export interface EventNode {
    id: string
    type: string
    timestamp: string
    pid?: number
    label: string
    is_finding?: boolean
    properties?: Record<string, unknown>
}

export interface EventEdge {
    from: string
    to: string
    type: string
}

export interface IncidentDetail extends Incident {
    findings: FindingSummary[]
    timeline: TimelineEntry[]
    process_tree?: ProcessNode
    event_graph?: { nodes: EventNode[]; edges: EventEdge[] }
}

export interface AIExplanation {
    content: string
    reasoning?: string
    model: string
    cached?: boolean
    risk_score?: number
    risk_justification?: string
    tokens: { input: number; output: number }
}

export async function getIncidents(params: {
    status?: string; severity?: string; host_id?: string; category?: string;
    since?: string; limit?: number; offset?: number;
} = {}): Promise<{ incidents: Incident[]; count: number; counts: IncidentCounts }> {
    const q = new URLSearchParams()
    if (params.status) q.set('status', params.status)
    if (params.severity) q.set('severity', params.severity)
    if (params.host_id) q.set('host_id', params.host_id)
    if (params.category) q.set('category', params.category)
    if (params.since) q.set('since', params.since)
    if (params.limit) q.set('limit', String(params.limit))
    if (params.offset) q.set('offset', String(params.offset))
    const qs = q.toString()
    return fetchJSON(`/api/v1/incidents${qs ? '?' + qs : ''}`)
}

export async function getIncident(id: string): Promise<IncidentDetail> {
    const resp = await fetchJSON<{ incident: IncidentDetail }>(`/api/v1/incidents/${encodeURIComponent(id)}`)
    return resp.incident
}

export async function updateIncidentStatus(id: string, status: string, resolution?: string): Promise<void> {
    await fetchJSON(`/api/v1/incidents/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, resolution: resolution || '' }),
    })
}

export async function explainIncident(id: string, detailLevel?: string): Promise<AIExplanation> {
    const params = detailLevel ? `?detail_level=${detailLevel}` : ''
    return fetchJSON<AIExplanation>(`/api/v1/incidents/${encodeURIComponent(id)}/explain${params}`, {
        method: 'POST',
    })
}

export async function askAboutIncident(id: string, message: string): Promise<AIExplanation> {
    return fetchJSON<AIExplanation>(`/api/v1/incidents/${encodeURIComponent(id)}/ask`, {
        method: 'POST',
        body: JSON.stringify({ message }),
    })
}

export async function streamAskAboutIncident(
    id: string,
    message: string,
    onDelta: (text: string) => void,
    onDone?: (stats: { model: string; tokens: { input: number; output: number } }) => void,
    onError?: (error: string) => void,
): Promise<void> {
    const resp = await fetch(`/api/proxy/api/v1/incidents/${encodeURIComponent(id)}/ask/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message }),
    })

    if (!resp.ok || !resp.body) {
        const err = await resp.text().catch(() => 'stream failed')
        onError?.(err)
        return
    }

    const reader = resp.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    try {
        while (true) {
            const { done, value } = await reader.read()
            if (done) break

            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n')
            buffer = lines.pop() || ''

            for (const line of lines) {
                if (!line.startsWith('data: ')) continue
                const data = line.slice(6)
                if (data === '[DONE]') return

                try {
                    const parsed = JSON.parse(data)
                    if (parsed.type === 'delta') onDelta(parsed.content)
                    else if (parsed.type === 'done') onDone?.({ model: parsed.model, tokens: parsed.tokens })
                    else if (parsed.type === 'error') onError?.(parsed.error)
                } catch { /* skip malformed SSE */ }
            }
        }
    } finally {
        reader.releaseLock()
    }
}

// --- Dossier-based threaded chat (replaces stateless ask/stream) ---

export interface ChatMessage {
    id: string
    role: 'user' | 'assistant'
    content: string
    token_count: number
    compressed: boolean
    created_at: string
}

export async function getChatHistory(incidentId: string, threadId: string): Promise<ChatMessage[]> {
    return fetchJSON<ChatMessage[]>(
        `/api/v1/incidents/${encodeURIComponent(incidentId)}/chat/history?thread_id=${encodeURIComponent(threadId)}`
    )
}

export async function deleteChatThread(incidentId: string, threadId: string): Promise<void> {
    await fetchJSON<void>(
        `/api/v1/incidents/${encodeURIComponent(incidentId)}/chat/thread/${encodeURIComponent(threadId)}`,
        { method: 'DELETE' }
    )
}

export async function streamChatAboutIncident(
    id: string,
    message: string,
    threadId: string | undefined,
    onThreadId: (threadId: string) => void,
    onDelta: (text: string) => void,
    onDone?: (stats: { model: string; tokens: { input: number; output: number } }) => void,
    onError?: (error: string) => void,
    onToolCall?: (tool: { name: string; status: 'running' | 'done' }) => void,
): Promise<void> {
    const resp = await fetch(`/api/proxy/api/v1/incidents/${encodeURIComponent(id)}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, thread_id: threadId || '' }),
    })

    if (!resp.ok || !resp.body) {
        const err = await resp.text().catch(() => 'stream failed')
        onError?.(err)
        return
    }

    const reader = resp.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    try {
        while (true) {
            const { done, value } = await reader.read()
            if (done) break

            buffer += decoder.decode(value, { stream: true })
            const lines = buffer.split('\n')
            buffer = lines.pop() || ''

            for (const line of lines) {
                if (!line.startsWith('data: ')) continue
                const data = line.slice(6)
                if (data === '[DONE]') return

                try {
                    const parsed = JSON.parse(data)
                    if (parsed.type === 'thread_id') onThreadId(parsed.thread_id)
                    else if (parsed.type === 'delta') onDelta(parsed.content)
                    else if (parsed.type === 'done') onDone?.({ model: parsed.model, tokens: parsed.tokens })
                    else if (parsed.type === 'error') onError?.(parsed.error)
                    else if (parsed.type === 'tool_call') onToolCall?.({ name: parsed.tool, status: parsed.status })
                } catch { /* skip malformed SSE */ }
            }
        }
    } finally {
        reader.releaseLock()
    }
}

export async function explainFinding(id: string): Promise<AIExplanation> {
    return fetchJSON<AIExplanation>(`/api/v1/findings/${encodeURIComponent(id)}/explain`, {
        method: 'POST',
    })
}

// --- Notifications (Phase 6) ---

export interface AppNotification {
    id: string
    org_id: string
    category: string
    severity: string
    title: string
    summary: string
    reference_type?: string
    reference_id?: string
    host_id?: string
    context?: Record<string, any>
    read: boolean
    dismissed: boolean
    created_at: string
}

export interface NotificationEndpoint {
    id: string
    org_id: string
    name: string
    channel_type: string
    config: Record<string, any>
    min_severity: string
    enabled: boolean
    created_at: string
    updated_at: string
}

export interface NotificationDelivery {
    id: string
    org_id: string
    endpoint_id: string
    reference_type: string
    reference_id: string
    payload: Record<string, any>
    status: string
    attempts: number
    max_attempts: number
    last_error: string
    next_attempt_at: string
    delivered_at?: string
    created_at: string
    updated_at: string
}

export async function getNotifications(unreadOnly = false, limit = 50): Promise<{ notifications: AppNotification[], count: number }> {
    const params = new URLSearchParams()
    if (unreadOnly) params.set('unread_only', 'true')
    if (limit !== 50) params.set('limit', String(limit))
    const qs = params.toString()
    return fetchJSON(`/api/v1/notifications${qs ? '?' + qs : ''}`)
}

export async function getNotificationCount(): Promise<{ unread_count: number }> {
    return fetchJSON('/api/v1/notifications/count')
}

export async function markNotificationRead(id: string): Promise<{ ok: boolean }> {
    return fetchJSON(`/api/v1/notifications/${encodeURIComponent(id)}/read`, { method: 'PATCH' })
}

export async function markAllNotificationsRead(): Promise<{ ok: boolean }> {
    return fetchJSON('/api/v1/notifications/read-all', { method: 'POST' })
}

export async function dismissNotification(id: string): Promise<{ ok: boolean }> {
    return fetchJSON(`/api/v1/notifications/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function getNotificationEndpoints(): Promise<{ endpoints: NotificationEndpoint[], count: number }> {
    const resp = await fetchJSON<{ endpoints: NotificationEndpoint[], count: number } | null>('/api/v1/notification-endpoints')
    return resp ?? { endpoints: [], count: 0 }
}

export async function createNotificationEndpoint(data: {
    name: string
    channel_type: string
    config: Record<string, any>
    min_severity?: string
    enabled?: boolean
}): Promise<{ endpoint: NotificationEndpoint }> {
    return fetchJSON('/api/v1/notification-endpoints', {
        method: 'POST',
        body: JSON.stringify(data),
    })
}

export async function updateNotificationEndpoint(id: string, data: Partial<{
    name: string
    channel_type: string
    config: Record<string, any>
    min_severity: string
    enabled: boolean
}>): Promise<{ endpoint: NotificationEndpoint }> {
    return fetchJSON(`/api/v1/notification-endpoints/${encodeURIComponent(id)}`, {
        method: 'PUT',
        body: JSON.stringify(data),
    })
}

export async function deleteNotificationEndpoint(id: string): Promise<{ ok: boolean }> {
    return fetchJSON(`/api/v1/notification-endpoints/${encodeURIComponent(id)}`, { method: 'DELETE' })
}

export async function testNotificationEndpoint(id: string): Promise<{ ok: boolean, error?: string }> {
    return fetchJSON(`/api/v1/notification-endpoints/${encodeURIComponent(id)}/test`, { method: 'POST' })
}

export async function getNotificationDeliveries(limit = 50): Promise<{ deliveries: NotificationDelivery[], count: number }> {
    return fetchJSON(`/api/v1/notification-deliveries?limit=${limit}`)
}

// User Profile
export interface UserProfile {
    id: string
    email: string
    name: string
    username: string
    avatar_url: string
    email_verified: boolean
    role: string
    created_at: string
}

export async function getUserProfile(): Promise<UserProfile> {
    return fetchJSON<UserProfile>('/auth/profile')
}

export async function updateUserProfile(data: {
    name?: string
    username?: string
    avatar_url?: string
}): Promise<UserProfile> {
    return fetchJSON<UserProfile>('/auth/profile', {
        method: 'PUT',
        body: JSON.stringify(data),
    })
}

// Google OAuth
export async function googleSignIn(idToken: string): Promise<{ token: string; session: any; user: any }> {
    return fetchJSON('/auth/google', {
        method: 'POST',
        body: JSON.stringify({ id_token: idToken }),
    })
}

// Email Verification
export async function sendVerificationEmail(email?: string): Promise<{ success: boolean; message: string }> {
    return fetchJSON('/auth/email/send-verification', {
        method: 'POST',
        body: JSON.stringify(email ? { email } : {}),
    })
}

export async function verifyEmail(token: string): Promise<{ success: boolean; message: string; email?: string }> {
    return fetchJSON('/auth/email/verify', {
        method: 'POST',
        body: JSON.stringify({ token }),
    })
}

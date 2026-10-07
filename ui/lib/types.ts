export type Severity = 'low' | 'medium' | 'high' | 'critical'

export interface Approval {
  id: string
  status: 'pending' | 'approved' | 'rejected'
  agent_id: string
  created_at: string
  reason?: string | null
  subject: Record<string, any> | null
  decided_at?: string | null
  kind?: string

}

export interface IdentityRecord {
  kind:
  | 'ssh_key'
  | 'git_repo'
  | 'git_remote_host'
  | 'kube_context'
  value: string
  first_seen_at: string
  last_seen_at: string
  seen_count: number
  last_event_id: string | null
  last_event_type: string | null
  last_meta: Record<string, any>
}


export interface AgentIdentityResponse {
  agent_id: string
  items: IdentityRecord[]
  by_kind: Record<string, IdentityRecord[]>
}

export interface AgentSummary {
  agent_id: string
  hostname?: string
  os?: string
  profile?: string
  version?: string
  state?: string
  liveness?: 'online' | 'stale' | 'offline'
  first_seen_at?: string
  last_seen_at?: string
}

export interface AgentDetail extends AgentSummary {
  liveness: 'online' | 'stale' | 'offline'
}

export interface PolicyRecord {
  key: string
  value: Record<string, any>
  updated_at?: string
}

export interface CorrelationPack {
  pack_id: string
  name: string
  version: string
  description?: string
  defaults?: {
    severity?: Severity
    actions?: string[]
  }
  policies?: CorrelationPolicyRule[]
  correlations?: CorrelationRule[]
}

export type CorrelationConditionOp = 'equals' | 'contains' | 'in' | 'regex' | 'gt' | 'lt'

export interface CorrelationCondition {
  field: string
  op: CorrelationConditionOp
  value: string | number | boolean | string[]
}

export interface CorrelationPolicyRule {
  id: string
  signal: string
  match?: {
    all?: CorrelationCondition[]
    any?: CorrelationCondition[]
    none?: CorrelationCondition[]
  }
  severity?: Severity
  actions?: string[]
  tags?: string[]
}

export interface CorrelationRule {
  id: string
  policy_ids: string[]
  window_minutes: number
  same_actor?: boolean
  same_repo?: boolean
  same_host?: boolean
  threshold?: number
  severity?: Severity
  actions?: string[]
}

export interface OrgRecord {
  id: string
  name: string
  created_at: string
  role?: 'admin' | 'member'
  actor_type?: string
  actor_id?: string
}

export interface UserRecord {
  id: string
  email: string
  name: string
  role?: string
  is_service_account?: boolean
  created_at?: string
}

export interface APIKeyRecord {
  id: string
  user_id?: string | null
  user_email?: string | null
  user_name?: string | null
  is_service_account?: boolean
  key_type?: string
  name: string
  description?: string
  created_at?: string
  revoked_at?: string | null
}

export interface NotificationEndpoint {
  id: string
  name?: string
  kind: string
  url: string
  webhook_url?: string
  secret?: string
  enabled: boolean
  created_at?: string
  updated_at?: string
}

export interface SupplyChainAllowlistEntry {
  org_id: string
  repo: string
  ecosystem: string
  package: string
  added_by?: string
  created_at?: string
}

export interface NotificationDelivery {
  id: string
  endpoint_id: string
  reference_type: string
  reference_id: string
  status: string
  attempts: number
  last_error?: string
  next_attempt_at?: string | null
  created_at?: string
  updated_at?: string
}

export interface TelemetryEvent {
  id?: string
  agent_id: string
  event_type: string
  timestamp: string
  payload: Record<string, any>
  received_at?: string
}

export interface GitHubInstallation {
  installation_id: number
  account_login?: string
  linked_at: string
  revoked_at?: string | null
}

export interface GitLabWebhookConfig {
  configured: boolean
  token_hint?: string
  updated_at?: string
}

// Signal types from eBPF probes
export type SignalType =
  | 'process_exec'
  | 'file_open'
  | 'file_delete'
  | 'net_connect'
  | 'net_bind'
  | 'dns_query'
  | 'privilege_change'
  | 'identity_snapshot'

// AI process names we track
export const AI_PROCESSES = [
  'cursor',
  'copilot',
  'claude',
  'code',     // VS Code
  'codeium',
  'tabnine',
  'aider',
  'continue', // Continue.dev
] as const

// Severity levels
export const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
} as const

// Enhanced telemetry event for UI
export interface EnhancedTelemetryEvent extends TelemetryEvent {
  is_ai_process?: boolean
  process_name?: string
  severity?: Severity
  rule_id?: string
}

// Port binding information
export interface PortBinding {
  port: number
  address: string
  protocol: 'tcp' | 'udp'
  process: string
  pid: number
  since?: string
}

// Network connection
export interface NetworkConnection {
  id: string
  agent_id: string
  local_addr: string
  remote_addr: string
  protocol: string
  process: string
  pid: number
  status: 'active' | 'closed'
  bytes_sent?: number
  bytes_recv?: number
  duration?: string
  created_at: string
}

// DNS query record
export interface DNSQuery {
  query: string
  query_type: string
  count: number
  last_seen_at: string
  is_suspicious?: boolean
}

// Policy template from backend
export interface PolicyTemplate {
  id: string
  signal: string
  name: string
  category: string
  description: string
  severity: Severity
}

export interface NetworkSummaryResponse {
  window: {
    since: string
    until: string
  }
  counts: {
    dns_queries: number
    net_connections: number
    suspicious_dns: number
    unique_domains: number
    unique_dest_addrs: number
  }
  top_domains: Array<{ domain: string; count: number }>
  top_destinations: Array<{ dst: string; count: number }>
}

export interface PortsSummaryResponse {
  window: {
    since: string
    until: string
  }
  counts: {
    open_services: number
    exposed: number
  }
  services: Array<{
    key: string
    port: number
    comm: string
    pcomm?: string
    addresses: string[]
    instances?: Array<{ pid: number; uid?: number }>
    risk?: string
    exposed: boolean
  }>
}

export interface AIProofResponse {
  generated_at: string
  window: {
    since: string
    until: string
    agent_id?: string
    include_non_ai: boolean
    include_localhost?: boolean
    include_private?: boolean
    include_external?: boolean
  }
  summary: {
    total_evidence_events: number
    secrets_touched: number
    dns_queries: number
    suspicious_dns?: number
    net_connections: number
    external_connections?: number
    exposed_binds: number
    process_execs: number
  }
  risk?: {
    score: number
    level: 'none' | 'low' | 'medium' | 'high' | 'critical' | string
    reasons?: string[]
  }
  previous?: {
    window: { since: string; until: string }
    summary: {
      secrets_touched: number
      dns_queries: number
      suspicious_dns: number
      net_connections: number
      external_connections: number
      exposed_binds: number
      process_execs: number
    }
    risk: { score: number }
  }
  delta?: {
    summary: {
      secrets_touched: number
      dns_queries: number
      suspicious_dns: number
      net_connections: number
      external_connections: number
      exposed_binds: number
      process_execs: number
    }
    risk: { score: number }
  }
  top_domains: Array<{ domain: string; count: number; allowlisted?: boolean }>
  top_destinations: Array<{ dst: string; count: number; external?: boolean; allowlisted?: boolean }>
  external_ips?: Array<{
    ip: string
    connections: number
    ports: number
    org?: string
    domains?: Array<{ domain: string; count: number; allowlisted?: boolean }>
  }>
  /** Total unique external IPs in window (list is top 25 by connection count). */
  external_ips_total?: number
  findings: {
    secrets: Array<{ path: string; category?: string; event_id?: string; event_ts: string }>
    exposed_ports: Array<{ bind_addr: string; bind_port: number; comm?: string; pcomm?: string; risk?: string; event_id?: string; event_ts: string }>
    execs: Array<{ comm?: string; pcomm?: string; exe?: string; event_id?: string; event_ts: string }>
  }
  evidence: TelemetryEvent[]
  /** Set when AI-only view includes events that match by name but have untrusted exe path (possible impersonation). */
  attribution_warning?: string
}

export interface GuardRecord {
  id: string
  name: string
  description: string
  tier: 'free' | 'pro' | string
  rules_total: number
  rules_enabled: number
  enabled: boolean
  partial: boolean
  policy_ids?: string[]
}

export interface GuardsResponse {
  guards: GuardRecord[]
}

export interface PortsServiceResponse {
  window: { since: string; until: string }
  service: {
    port: number
    comm: string
    pcomm?: string
    pid: number
    uid?: number
    addresses: string[]
    risk?: string
    exposed: boolean
  }
  reasons?: string[]
  events: TelemetryEvent[]
}

export interface NetworkDomainResponse {
  window: { since: string; until: string }
  domain: string
  counts: {
    dns_queries: number
    suspicious_dns: number
    pids: number
    connections: number
  }
  top_pids?: Array<{ pid: number; comm?: string; count: number }>
  evidence: TelemetryEvent[]
}

export interface NetworkDestinationResponse {
  window: { since: string; until: string }
  dst_ip: string
  dst_port?: number
  counts: {
    connections: number
    pids: number
  }
  top_pids?: Array<{ pid: number; comm?: string; count: number }>
  org?: string
  observed_domains?: Array<{ domain: string; count: number }>
  evidence: TelemetryEvent[]
}


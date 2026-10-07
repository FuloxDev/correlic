import { fetchJSON } from './api'
import {
  AgentIdentityResponse,
  AgentDetail,
  AgentSummary,
  Approval,
  PolicyRecord,
  OrgRecord,
  UserRecord,
  APIKeyRecord,
  NotificationEndpoint,
  NotificationDelivery,
  GitHubInstallation,
  GitLabWebhookConfig,
  SupplyChainAllowlistEntry,
  TelemetryEvent,
  PolicyTemplate,
  NetworkSummaryResponse,
  PortsSummaryResponse,
  AIProofResponse,
  GuardsResponse,
  PortsServiceResponse,
  NetworkDomainResponse,
  NetworkDestinationResponse,
} from './types'


export const getPolicies = (): Promise<PolicyRecord[]> =>
  fetchJSON('/policies')

export const getPolicy = (key: string): Promise<PolicyRecord> =>
  fetchJSON(`/policies/${key}`)

export const putPolicy = (
  key: string,
  value: Record<string, any>
): Promise<PolicyRecord> =>
  fetchJSON(`/policies/${key}`, {
    method: 'PUT',
    body: JSON.stringify(value ?? {}),
  })

export const getOrgMe = (): Promise<OrgRecord> =>
  fetchJSON('/orgs/me')

export const getAgent = async (agentId: string): Promise<AgentDetail> =>
  fetchJSON(`/agents/${agentId}`)

export const getApprovals = (opts?: {
  status?: 'pending' | 'approved' | 'rejected'
  agentId?: string
  limit?: number
}): Promise<Approval[]> => {
  const params = new URLSearchParams()
  if (opts?.status) {
    params.set('status', opts.status)
  }
  if (opts?.agentId) {
    params.set('agent_id', opts.agentId)
  }
  if (opts?.limit) {
    params.set('limit', String(opts.limit))
  }
  const qs = params.toString()
  return fetchJSON(`/approvals${qs ? `?${qs}` : ''}`)
}

export const decideApproval = (
  id: string,
  status: 'approved' | 'rejected',
  reason: string
): Promise<void> =>
  fetchJSON(`/approvals/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, reason }),
  })

export const getApproval = (id: string): Promise<Approval> =>
  fetchJSON(`/approvals/${id}`)

export const getUsers = (): Promise<UserRecord[]> =>
  fetchJSON('/users')

export const createUser = (
  email: string,
  name: string,
  role: string,
  isServiceAccount: boolean = false
): Promise<UserRecord & { password?: string; password_reset_required?: boolean }> =>
  fetchJSON('/users', {
    method: 'POST',
    body: JSON.stringify({ email, name, role, is_service_account: isServiceAccount }),
  })

export const updateUser = (
  userId: string,
  name?: string,
  role?: string
): Promise<UserRecord> =>
  fetchJSON(`/users?user_id=${encodeURIComponent(userId)}`, {
    method: 'PUT',
    body: JSON.stringify({ name, role }),
  })

export const deleteUser = (userId: string): Promise<{ success: boolean; message: string }> =>
  fetchJSON(`/users?user_id=${encodeURIComponent(userId)}`, {
    method: 'DELETE',
  })

export const getAPIKeys = (): Promise<APIKeyRecord[]> =>
  fetchJSON('/api-keys')

export const createAPIKey = (
  userId: string,
  name: string,
  description?: string
): Promise<{ id: string; api_key: string; name: string }> =>
  fetchJSON('/api-keys', {
    method: 'POST',
    body: JSON.stringify({ user_id: userId, name, description: description ?? '' }),
  })

export const revokeAPIKey = (keyId: string): Promise<{ success: boolean; message: string }> =>
  fetchJSON(`/api-keys?key_id=${encodeURIComponent(keyId)}`, {
    method: 'DELETE',
  })

export const createAgentToken = (
  name?: string,
  description?: string
): Promise<{ id: string; api_key: string; name: string; type: string }> =>
  fetchJSON('/agent-tokens', {
    method: 'POST',
    body: JSON.stringify({ name: name ?? '', description: description ?? '' }),
  })

export const getNotifications = (): Promise<NotificationEndpoint[]> =>
  fetchJSON('/notifications')

export const createNotification = (
  payload: Omit<NotificationEndpoint, 'id'>
): Promise<NotificationEndpoint> =>
  fetchJSON('/notifications', {
    method: 'POST',
    body: JSON.stringify(payload),
  })

export const updateNotification = (
  id: string,
  payload: Partial<NotificationEndpoint>
): Promise<NotificationEndpoint> =>
  fetchJSON(`/notifications/${id}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })

export const getNotificationDeliveries = (opts?: {
  status?: string
  limit?: number
  offset?: number
}): Promise<NotificationDelivery[]> => {
  const params = new URLSearchParams()
  if (opts?.status) params.set('status', opts.status)
  if (opts?.limit) params.set('limit', String(opts.limit))
  if (opts?.offset) params.set('offset', String(opts.offset))
  const qs = params.toString()
  return fetchJSON(`/notifications/deliveries${qs ? `?${qs}` : ''}`)
}

export const getSupplyChainAllowlist = (opts?: {
  repo?: string
  ecosystem?: string
  limit?: number
}): Promise<SupplyChainAllowlistEntry[]> => {
  const params = new URLSearchParams()
  if (opts?.repo) params.set('repo', opts.repo)
  if (opts?.ecosystem) params.set('ecosystem', opts.ecosystem)
  if (opts?.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/supply-chain/allowlist${qs ? `?${qs}` : ''}`)
}

export const addSupplyChainAllowlist = (
  repo: string,
  ecosystem: string,
  packages: string[]
): Promise<void> =>
  fetchJSON('/supply-chain/allowlist', {
    method: 'POST',
    body: JSON.stringify({ repo, ecosystem, packages }),
  })

export const removeSupplyChainAllowlist = (
  repo: string,
  ecosystem: string,
  pkg: string
): Promise<void> =>
  fetchJSON(
    `/supply-chain/allowlist?repo=${encodeURIComponent(repo)}&ecosystem=${encodeURIComponent(ecosystem)}&package=${encodeURIComponent(pkg)}`,
    { method: 'DELETE' }
  )

export type ManifestImportType = 'package.json' | 'go.mod' | 'requirements.txt' | 'Pipfile'

export const importSupplyChainAllowlist = (
  repo: string,
  manifestType: ManifestImportType,
  content: string
): Promise<{ added: number; ecosystem: string; packages: string[] }> =>
  fetchJSON('/supply-chain/allowlist/import', {
    method: 'POST',
    body: JSON.stringify({ repo, manifest_type: manifestType, content }),
  })

export const getScmRepos = (
  provider: 'github' | 'gitlab',
  limit?: number
): Promise<string[]> => {
  const params = new URLSearchParams({ provider })
  if (limit) params.set('limit', String(limit))
  return fetchJSON(`/scm/repos?${params.toString()}`)
}

export const getScmBranches = (
  provider: 'github' | 'gitlab',
  repo: string,
  limit?: number
): Promise<string[]> => {
  const params = new URLSearchParams({ provider, repo })
  if (limit) params.set('limit', String(limit))
  return fetchJSON(`/scm/branches?${params.toString()}`)
}


export const getAgents = async (): Promise<AgentSummary[]> =>
  fetchJSON('/agents')

export const getAgentIdentity = (
  agentId: string,
  opts?: { kind?: string; limit?: number }
): Promise<AgentIdentityResponse> => {
  const params = new URLSearchParams()
  if (opts?.kind) params.set('kind', opts.kind)
  if (opts?.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/agents/${agentId}/identity${qs ? `?${qs}` : ''}`)
}

// GitHub Installations
export const getGitHubInstallations = (opts?: {
  includeRevoked?: boolean
  limit?: number
}): Promise<GitHubInstallation[]> => {
  const params = new URLSearchParams()
  if (opts?.includeRevoked) params.set('include_revoked', 'true')
  if (opts?.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/github/installations${qs ? `?${qs}` : ''}`)
}

export const linkGitHubInstallation = (
  installationId: number,
  accountLogin?: string
): Promise<{ linked: boolean; installation_id: number }> =>
  fetchJSON('/github/installations', {
    method: 'POST',
    body: JSON.stringify({
      installation_id: installationId,
      account_login: accountLogin ?? '',
    }),
  })

export const revokeGitHubInstallation = (
  installationId: number
): Promise<{ revoked: boolean; installation_id: number }> =>
  fetchJSON(`/github/installations?installation_id=${installationId}`, {
    method: 'DELETE',
  })

// GitLab webhooks (org-scoped token config)
export const getGitLabWebhook = (): Promise<GitLabWebhookConfig> =>
  fetchJSON('/gitlab/webhook')

export const setGitLabWebhook = (token: string): Promise<GitLabWebhookConfig> =>
  fetchJSON('/gitlab/webhook', {
    method: 'PUT',
    body: JSON.stringify({ token }),
  })

export const clearGitLabWebhook = (): Promise<{ removed: boolean }> =>
  fetchJSON('/gitlab/webhook', {
    method: 'DELETE',
  })

// Telemetry events (for Live Feed / AI Activity)
export const getTelemetryEvents = (opts?: {
  agentId?: string
  eventType?: string
  since?: string
  until?: string
  pid?: number
  limit?: number
  offset?: number
  aiOnly?: boolean  // Filter to AI processes only
}): Promise<TelemetryEvent[]> => {
  const params = new URLSearchParams()
  if (opts?.agentId) params.set('agent_id', opts.agentId)
  if (opts?.eventType) params.set('event_type', opts.eventType)
  if (opts?.since) params.set('since', opts.since)
  if (opts?.until) params.set('until', opts.until)
  if (opts?.pid) params.set('pid', String(opts.pid))
  if (opts?.limit) params.set('limit', String(opts.limit))
  if (opts?.offset) params.set('offset', String(opts.offset))
  if (opts?.aiOnly) params.set('ai_only', 'true')
  const qs = params.toString()
  return fetchJSON(`/telemetry${qs ? `?${qs}` : ''}`)
}

// Policy templates
export const getPolicyTemplates = (): Promise<{ templates: PolicyTemplate[] }> =>
  fetchJSON('/policies/templates')

// Dashboard stats
export interface DashboardStats {
  total_events_today: number
  open_findings: number
  ai_processes_active: number
  open_ports: number
  active_connections: number
}

export const getDashboardStats = (): Promise<DashboardStats> =>
  fetchJSON('/dashboard/stats')

export const getNetworkSummary = (opts?: {
  agentId?: string
  since?: string
  until?: string
}): Promise<NetworkSummaryResponse> => {
  const params = new URLSearchParams()
  if (opts?.agentId) params.set('agent_id', opts.agentId)
  if (opts?.since) params.set('since', opts.since)
  if (opts?.until) params.set('until', opts.until)
  const qs = params.toString()
  return fetchJSON(`/network/summary${qs ? `?${qs}` : ''}`)
}

export const getPortsSummary = (opts?: {
  agentId?: string
  since?: string
  until?: string
}): Promise<PortsSummaryResponse> => {
  const params = new URLSearchParams()
  if (opts?.agentId) params.set('agent_id', opts.agentId)
  if (opts?.since) params.set('since', opts.since)
  if (opts?.until) params.set('until', opts.until)
  const qs = params.toString()
  return fetchJSON(`/ports/summary${qs ? `?${qs}` : ''}`)
}

export const getAIProof = (opts?: {
  agentId?: string
  since?: string
  until?: string
  includeNonAI?: boolean
  includeLocalhost?: boolean
  includePrivate?: boolean
  includeExternal?: boolean
}): Promise<AIProofResponse> => {
  const params = new URLSearchParams()
  if (opts?.agentId) params.set('agent_id', opts.agentId)
  if (opts?.since) params.set('since', opts.since)
  if (opts?.until) params.set('until', opts.until)
  if (opts?.includeNonAI) params.set('include_non_ai', 'true')
  if (opts?.includeLocalhost !== undefined) params.set('include_localhost', opts.includeLocalhost ? 'true' : 'false')
  if (opts?.includePrivate !== undefined) params.set('include_private', opts.includePrivate ? 'true' : 'false')
  if (opts?.includeExternal !== undefined) params.set('include_external', opts.includeExternal ? 'true' : 'false')
  const qs = params.toString()
  return fetchJSON(`/ai/proof${qs ? `?${qs}` : ''}`)
}

export const getGuards = (): Promise<GuardsResponse> =>
  fetchJSON('/guards')

export const setGuardEnabled = (id: string, enabled: boolean): Promise<GuardsResponse> =>
  fetchJSON(`/guards/${encodeURIComponent(id)}`, {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  })

export const getPortsService = (opts: {
  agentId?: string
  port: number
  pid?: number
  comm?: string
  since?: string
  until?: string
  limit?: number
}): Promise<PortsServiceResponse> => {
  const params = new URLSearchParams()
  if (opts.agentId) params.set('agent_id', opts.agentId)
  params.set('port', String(opts.port))
  if (opts.pid) params.set('pid', String(opts.pid))
  if (opts.comm) params.set('comm', opts.comm)
  if (opts.since) params.set('since', opts.since)
  if (opts.until) params.set('until', opts.until)
  if (opts.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/ports/service?${qs}`)
}

export const getNetworkDomain = (opts: {
  agentId?: string
  domain: string
  since?: string
  until?: string
  limit?: number
}): Promise<NetworkDomainResponse> => {
  const params = new URLSearchParams()
  if (opts.agentId) params.set('agent_id', opts.agentId)
  params.set('domain', opts.domain)
  if (opts.since) params.set('since', opts.since)
  if (opts.until) params.set('until', opts.until)
  if (opts.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/network/domain?${qs}`)
}

export const getNetworkDestination = (opts: {
  agentId?: string
  dst: string
  since?: string
  until?: string
  limit?: number
}): Promise<NetworkDestinationResponse> => {
  const params = new URLSearchParams()
  if (opts.agentId) params.set('agent_id', opts.agentId)
  params.set('dst', opts.dst)
  if (opts.since) params.set('since', opts.since)
  if (opts.until) params.set('until', opts.until)
  if (opts.limit) params.set('limit', String(opts.limit))
  const qs = params.toString()
  return fetchJSON(`/network/destination?${qs}`)
}
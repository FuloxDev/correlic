import type { TelemetryEvent } from '@/lib/types'

export type TimelineCategory =
  | 'Ports'
  | 'Network'
  | 'Files'
  | 'Process'
  | 'Privilege'
  | 'Other'

export type FileKind = 'credential-ish' | 'repo-file' | 'other-file'

export function classifyFilePath(path: unknown): FileKind {
  const p = String(path || '').trim()
  if (!p) return 'other-file'
  const lower = p.toLowerCase()

  const credentialHints = [
    '.ssh',
    '.aws',
    '.kube',
    '.gnupg',
    '.gpg',
    '.azure',
    'gcloud',
    'login data',
    'logins.json',
    'cookies',
    '.npmrc',
    '.pypirc',
    '.netrc',
    '.git-credentials',
    '.env',
    'id_rsa',
    'id_ed25519',
    'known_hosts',
    'authorized_keys',
    'credentials',
    'token',
    'apikey',
    'api_key',
    'secret',
  ]
  if (credentialHints.some(h => lower.includes(h))) return 'credential-ish'

  if (lower.includes('/.git/')) return 'repo-file'
  const repoNames = [
    'package.json',
    'package-lock.json',
    'pnpm-lock.yaml',
    'yarn.lock',
    'go.mod',
    'go.sum',
    'cargo.toml',
    'cargo.lock',
    'requirements.txt',
    'pyproject.toml',
    'poetry.lock',
    'dockerfile',
    'docker-compose.yml',
    'docker-compose.yaml',
    'makefile',
    '.gitignore',
    '.gitattributes',
    'tsconfig.json',
  ]
  if (repoNames.some(n => lower.endsWith('/' + n) || lower.endsWith(n)))
    return 'repo-file'

  const ext = lower.split('.').pop() || ''
  const codeExts = new Set([
    'go',
    'ts',
    'tsx',
    'js',
    'jsx',
    'py',
    'rb',
    'rs',
    'java',
    'kt',
    'c',
    'cc',
    'cpp',
    'h',
    'hpp',
    'json',
    'yaml',
    'yml',
    'toml',
    'md',
    'sql',
    'sh',
  ])
  if (codeExts.has(ext)) return 'repo-file'

  return 'other-file'
}

export function shortenPath(path: string, max = 64): string {
  const p = String(path || '')
  if (p.length <= max) return p
  // Keep filename + a bit of prefix
  const parts = p.split('/')
  const tail = parts[parts.length - 1] || p.slice(-12)
  const headBudget = Math.max(8, max - tail.length - 3)
  return `${p.slice(0, headBudget)}…/${tail}`
}

export function labelFilePath(path: string): { label: string; kindHint?: string } {
  const raw = String(path || '')
  const lower = raw.toLowerCase()
  // Docker overlay paths are a common source of unreadable noise; keep as a short label.
  if (lower.includes('/var/lib/docker/overlay2/')) {
    const short = shortenPath(raw, 56)
    return { label: short, kindHint: 'docker overlay' }
  }
  return { label: shortenPath(raw, 64) }
}

export function isLikelyNoise(e: TelemetryEvent): boolean {
  const p = e.payload || {}

  // net_connect to port 0 is almost always not useful for humans.
  if (e.event_type === 'net_connect') {
    const dstPort = Number(p.dst_port || 0) || 0
    if (dstPort === 0) return true
  }

  // privilege_change with no delta is usually internal churn.
  if (e.event_type === 'privilege_change') {
    const oldUid = p.old_uid
    const newUid = p.new_uid
    const oldEuid = p.old_euid
    const newEuid = p.new_euid
    const oldSuid = p.old_suid
    const newSuid = p.new_suid
    const hasUid = oldUid != null || newUid != null
    const hasEuid = oldEuid != null || newEuid != null
    const hasSuid = oldSuid != null || newSuid != null
    const noDelta =
      (!hasUid || String(oldUid) === String(newUid)) &&
      (!hasEuid || String(oldEuid) === String(newEuid)) &&
      (!hasSuid || String(oldSuid) === String(newSuid))
    if (noDelta) return true
  }

  return false
}

export function categorizeEvent(e: TelemetryEvent): TimelineCategory {
  switch (e.event_type) {
    case 'net_bind':
    case 'port_lifecycle':
      return 'Ports'
    case 'net_connect':
    case 'dns_query':
      return 'Network'
    case 'file_open':
    case 'file_delete':
      return 'Files'
    case 'process_exec':
      return 'Process'
    case 'privilege_change':
      return 'Privilege'
    default:
      return 'Other'
  }
}

export function formatTimelineDetail(e: TelemetryEvent): { text: string; key: string } {
  const p = e.payload || {}
  switch (e.event_type) {
    case 'file_open':
    case 'file_delete': {
      const raw = String(p.path || '')
      const category = p.category ? String(p.category) : ''
      const { label, kindHint } = raw ? labelFilePath(raw) : { label: '' }
      const suffix = [category, kindHint].filter(Boolean).join(', ')
      const text = suffix ? `${label} (${suffix})` : label
      return { text, key: `${e.event_type}|${raw}|${category}` }
    }
    case 'net_connect': {
      const ip = String(p.dst_ip || '')
      const port = p.dst_port != null ? String(p.dst_port) : ''
      const cat = p.category ? String(p.category) : ''
      const addr = ip ? `${ip}${port ? `:${port}` : ''}` : ''
      const text = cat ? `${addr} (${cat})` : addr
      return { text, key: `${e.event_type}|${ip}|${port}|${cat}` }
    }
    case 'dns_query': {
      const q = String(p.query || p.name || '')
      const dst = p.dst_ip ? String(p.dst_ip) : ''
      const text = [q, dst].filter(Boolean).join(' ')
      return { text, key: `${e.event_type}|${q}|${dst}` }
    }
    case 'net_bind': {
      const addr = String(p.bind_addr || '')
      const port = p.bind_port != null ? String(p.bind_port) : ''
      const text = `${addr}${port ? `:${port}` : ''}`.trim()
      return { text, key: `${e.event_type}|${addr}|${port}` }
    }
    case 'port_lifecycle': {
      const ev = String(p.event || '')
      const addr = String(p.bind_addr || '')
      const port = p.port != null ? String(p.port) : ''
      const reason = p.reason ? String(p.reason) : ''
      const label = ev === 'closed' && reason === 'rebind' ? 'restart' : ev
      const base = `${label}${addr || port ? ` ${addr}${port ? `:${port}` : ''}` : ''}`.trim()
      const text = reason && label !== 'restart' ? `${base} (${reason})` : base
      // Dedupe rebind chatter as "restart" key.
      const isRestart = ev === 'closed' && reason === 'rebind'
      return { text, key: `${e.event_type}|${isRestart ? 'restart' : ev}|${addr}|${port}` }
    }
    case 'process_exec': {
      const exe = String(p.exe || '')
      const comm = String(p.comm || '')
      const text = exe || comm
      return { text, key: `${e.event_type}|${exe || comm}` }
    }
    case 'privilege_change': {
      const oldUid = p.old_uid != null ? String(p.old_uid) : ''
      const newUid = p.new_uid != null ? String(p.new_uid) : ''
      const oldEuid = p.old_euid != null ? String(p.old_euid) : ''
      const newEuid = p.new_euid != null ? String(p.new_euid) : ''
      const oldSuid = p.old_suid != null ? String(p.old_suid) : ''
      const newSuid = p.new_suid != null ? String(p.new_suid) : ''

      const isEsc = Boolean(p.is_escalation)
      const isDrop = Boolean(p.is_dropping)
      const kind = isEsc ? 'escalation' : isDrop ? 'drop' : 'change'
      const syscall = p.syscall ? String(p.syscall) : ''

      const parts: string[] = []
      if (oldUid || newUid) parts.push(`uid ${oldUid || '?'}→${newUid || '?'}`)
      if (oldEuid || newEuid) parts.push(`euid ${oldEuid || '?'}→${newEuid || '?'}`)
      if (oldSuid || newSuid) parts.push(`suid ${oldSuid || '?'}→${newSuid || '?'}`)

      const base = parts.length ? parts.join(' ') : 'privilege change'
      const tail = [kind, syscall].filter(Boolean).join(', ')
      const text = tail ? `${base} (${tail})` : base
      const key = `${e.event_type}|${oldUid}|${newUid}|${oldEuid}|${newEuid}|${oldSuid}|${newSuid}|${kind}|${syscall}`
      return { text, key }
    }
    default: {
      const text = String(p.path || p.target || p.file || p.dst_ip || p.bind_addr || p.exe || '')
      return { text, key: `${e.event_type}|${text}` }
    }
  }
}

export type Burst = {
  key: string
  label: string
  first: TelemetryEvent
  last: TelemetryEvent
  count: number
  events: TelemetryEvent[]
}

export function groupBursts(events: TelemetryEvent[], windowMs = 1500): Burst[] {
  if (!events || events.length === 0) return []
  const sorted = [...events].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )

  const out: Burst[] = []
  let cur: Burst | null = null

  for (const e of sorted) {
    const { text, key } = formatTimelineDetail(e)
    const t = new Date(e.timestamp).getTime()

    if (!cur) {
      cur = { key, label: text, first: e, last: e, count: 1, events: [e] }
      continue
    }

    const lastT = new Date(cur.last.timestamp).getTime()
    const same = cur.key === key
    const close = t - lastT <= windowMs

    if (same && close) {
      cur.last = e
      cur.count += 1
      cur.events.push(e)
      continue
    }

    out.push(cur)
    cur = { key, label: text, first: e, last: e, count: 1, events: [e] }
  }
  if (cur) out.push(cur)
  return out
}

export type TimelineFacts = {
  ports: { opened: number; closed: number; restarts: number }
  network: { uniqueEndpoints: number; totalConnects: number; dnsConnects: number }
  files: { credential: number; repo: number; other: number }
  privilege: { changes: number; noisy: number }
}

export function buildTimelineFacts(events: TelemetryEvent[]): TimelineFacts {
  const facts: TimelineFacts = {
    ports: { opened: 0, closed: 0, restarts: 0 },
    network: { uniqueEndpoints: 0, totalConnects: 0, dnsConnects: 0 },
    files: { credential: 0, repo: 0, other: 0 },
    privilege: { changes: 0, noisy: 0 },
  }

  const endpoints = new Set<string>()
  for (const e of events || []) {
    const p = e.payload || {}
    if (e.event_type === 'port_lifecycle') {
      const ev = String(p.event || '')
      const reason = p.reason ? String(p.reason) : ''
      if (ev === 'opened') facts.ports.opened += 1
      if (ev === 'closed') facts.ports.closed += 1
      if (ev === 'closed' && reason === 'rebind') facts.ports.restarts += 1
    }
    if (e.event_type === 'net_connect') {
      facts.network.totalConnects += 1
      const ip = String(p.dst_ip || '')
      const port = p.dst_port != null ? String(p.dst_port) : ''
      if (ip && port) endpoints.add(`${ip}:${port}`)
      if (String(p.category || '') === 'dns' || String(port) === '53') facts.network.dnsConnects += 1
    }
    if (e.event_type === 'file_open' || e.event_type === 'file_delete') {
      const kind = classifyFilePath(p.path)
      if (kind === 'credential-ish') facts.files.credential += 1
      else if (kind === 'repo-file') facts.files.repo += 1
      else facts.files.other += 1
    }
    if (e.event_type === 'privilege_change') {
      facts.privilege.changes += 1
      if (isLikelyNoise(e)) facts.privilege.noisy += 1
    }
  }
  facts.network.uniqueEndpoints = endpoints.size
  return facts
}


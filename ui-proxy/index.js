import 'dotenv/config'
import express from 'express'
import fs from 'fs'
import https from 'https'
import fetch from 'node-fetch'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'


/**
 * Basic safety: this proxy is LOCAL ONLY
 * Never expose publicly.
 */

const app = express()

// Allow CORS from localhost (dev) and production domain
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3000', 'http://localhost:3001']

app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true)
      if (allowedOrigins.includes(origin)) {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-User-Email'],
    optionsSuccessStatus: 204,
    credentials: true,
  })
)
app.options(/.*/, cors())
app.use(express.json({ limit: '1mb' }))

// Health check endpoint
app.get('/health', (_req, res) => res.json({ status: 'ok' }))

const {
  PORT = 8788,
  BACKEND_API,
  API_KEY,
  MTLS_CA,
  MTLS_CERT,
  MTLS_KEY,
} = process.env

if (!BACKEND_API) {
  throw new Error('Missing required env var: BACKEND_API')
}

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

function mustReadPEM(label, p) {
  if (!p || String(p).trim() === '') {
    throw new Error(`[ui-proxy] Missing ${label} (env var not set)`)
  }
  const resolved = path.isAbsolute(p) ? p : path.resolve(__dirname, p)
  try {
    const data = fs.readFileSync(resolved)
    return { resolved, data }
  } catch (e) {
    throw new Error(`[ui-proxy] Failed to read ${label} at ${resolved}: ${e?.message || String(e)}`)
  }
}

/**
 * HTTPS agent with mTLS
 */
const ca = mustReadPEM('MTLS_CA', MTLS_CA)
const cert = mustReadPEM('MTLS_CERT', MTLS_CERT)
const key = mustReadPEM('MTLS_KEY', MTLS_KEY)

console.log('[ui-proxy] Using mTLS files:', {
  MTLS_CA: ca.resolved,
  MTLS_CERT: cert.resolved,
  MTLS_KEY: key.resolved,
})

const httpsAgent = new https.Agent({
  ca: ca.data,
  cert: cert.data,
  key: key.data,
  rejectUnauthorized: true, // DO NOT disable
})

/**
 * Generic proxy handler
 */
async function proxy(req, res, baseUrl) {
  try {
    const url = new URL(req.originalUrl, baseUrl)

    console.log('Proxying:', {
      method: req.method,
      url: url.toString(),
      baseUrl,
    })

    const headers = {
      'Content-Type': 'application/json',
    }

    const upstreamAuth =
      req.headers.authorization || req.headers['x-api-key']
    if (upstreamAuth && String(upstreamAuth).trim() !== '') {
      headers['Authorization'] = String(upstreamAuth)
      console.log('[UI Proxy] Using Authorization header from request')
    } else if (API_KEY && API_KEY.trim() !== '' && API_KEY !== '<RAW_API_KEY>') {
      headers['Authorization'] = API_KEY
      console.log('[UI Proxy] Using API_KEY from environment (fallback)')
    } else {
      console.warn('[UI Proxy] No API key found in request or environment')
    }
    if (req.headers['x-user-email']) {
      headers['X-User-Email'] = String(req.headers['x-user-email'])
    }
    const options = {
      method: req.method,
      agent: httpsAgent,
      headers
    }

    if (req.method !== 'GET' && req.body) {
      options.body = JSON.stringify(req.body)
    }

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 60_000) // 60s
    let upstream
    try {
      upstream = await fetch(url, { ...options, signal: controller.signal })
    } finally {
      clearTimeout(timeoutId)
    }
    const body = await upstream.text()

    res.status(upstream.status)
    res.set(
      'Content-Type',
      upstream.headers.get('content-type') || 'application/json'
    )
    res.send(body)
  } catch (err) {
    console.error('Proxy error:', err.message)
    console.error(err)
    res.status(502).json({ error: 'Upstream request failed' })
  }
}

/**
 * Approval routes (served by API server, not telemetry)
 */
app.get('/approvals', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.get('/approvals/:id', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.post('/approvals/:id', (req, res) =>
  proxy(req, res, BACKEND_API)
)

/**
 * Control plane routes
 */
app.get('/agents/:agent_id/identity', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.get('/agents', (req, res) => proxy(req, res, BACKEND_API))

app.get('/agents/:agent_id', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.get('/policies', (req, res) => proxy(req, res, BACKEND_API))

app.get('/policies/:key', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.put('/policies/:key', (req, res) =>
  proxy(req, res, BACKEND_API)
)

app.get('/orgs/me', (req, res) => proxy(req, res, BACKEND_API))

app.get('/users', (req, res) => proxy(req, res, BACKEND_API))
app.post('/users', (req, res) => proxy(req, res, BACKEND_API))
app.put('/users', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/users', (req, res) => proxy(req, res, BACKEND_API))

app.get('/api-keys', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api-keys', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api-keys', (req, res) => proxy(req, res, BACKEND_API))

app.post('/agent-tokens', (req, res) => proxy(req, res, BACKEND_API))

app.post('/auth/sessions', (req, res) => proxy(req, res, BACKEND_API))
app.post('/auth/password/reset', (req, res) => proxy(req, res, BACKEND_API))
app.post('/auth/signup', (req, res) => proxy(req, res, BACKEND_API))
app.post('/auth/verify-email', (req, res) => proxy(req, res, BACKEND_API))

// User profile (self-service)
app.get('/auth/profile', (req, res) => proxy(req, res, BACKEND_API))
app.put('/auth/profile', (req, res) => proxy(req, res, BACKEND_API))

// Email verification
app.post('/auth/email/send-verification', (req, res) => proxy(req, res, BACKEND_API))
app.post('/auth/email/verify', (req, res) => proxy(req, res, BACKEND_API))

app.get('/github/installations', (req, res) => proxy(req, res, BACKEND_API))
app.post('/github/installations', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/github/installations', (req, res) => proxy(req, res, BACKEND_API))

// GitLab integration config (org-scoped)
app.get('/gitlab/webhook', (req, res) => proxy(req, res, BACKEND_API))
app.put('/gitlab/webhook', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/gitlab/webhook', (req, res) => proxy(req, res, BACKEND_API))

// Supply chain allowlist (org-scoped)
app.get('/supply-chain/allowlist', (req, res) => proxy(req, res, BACKEND_API))
app.post('/supply-chain/allowlist/import', (req, res) => proxy(req, res, BACKEND_API))
app.post('/supply-chain/allowlist', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/supply-chain/allowlist', (req, res) => proxy(req, res, BACKEND_API))

// SCM repo/branch selectors
app.get('/scm/repos', (req, res) => proxy(req, res, BACKEND_API))
app.get('/scm/branches', (req, res) => proxy(req, res, BACKEND_API))

// Telemetry events (UI dashboard)
app.get('/telemetry', (req, res) => proxy(req, res, BACKEND_API))

// Tier + limits
app.get('/tier', (req, res) => proxy(req, res, BACKEND_API))

// Guards facade (correlation_pack grouped)
app.get('/guards', (req, res) => proxy(req, res, BACKEND_API))
app.post('/guards/:id', (req, res) => proxy(req, res, BACKEND_API))

// Summary / drilldowns
app.get('/network/summary', (req, res) => proxy(req, res, BACKEND_API))
app.get('/network/domain', (req, res) => proxy(req, res, BACKEND_API))
app.get('/network/destination', (req, res) => proxy(req, res, BACKEND_API))
app.get('/ports/summary', (req, res) => proxy(req, res, BACKEND_API))
app.get('/ports/service', (req, res) => proxy(req, res, BACKEND_API))

// AI Proof report
app.get('/ai/proof', (req, res) => proxy(req, res, BACKEND_API))

// Dashboard stats & baselines
app.get('/dashboard/stats', (req, res) => proxy(req, res, BACKEND_API))
app.get('/dashboard/trends', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/baselines', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/baselines', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/baselines/summary', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/baselines/noise-filters', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/baselines/safe-domains', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/baselines/safe-domains', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/baselines/safe-domains/:id', (req, res) => proxy(req, res, BACKEND_API))

// Process timeline (interactive view)
app.get('/processes/tree', (req, res) => proxy(req, res, BACKEND_API))
app.get('/processes/activity', (req, res) => proxy(req, res, BACKEND_API))
app.post('/processes/summary', (req, res) => proxy(req, res, BACKEND_API))

// Policy templates
app.get('/policies/templates', (req, res) => proxy(req, res, BACKEND_API))

app.get('/notifications', (req, res) =>
  proxy(req, res, BACKEND_API)
)
app.post('/notifications', (req, res) =>
  proxy(req, res, BACKEND_API)
)
app.put('/notifications/:id', (req, res) =>
  proxy(req, res, BACKEND_API)
)
app.get('/notifications/deliveries', (req, res) =>
  proxy(req, res, BACKEND_API)
)

// AI endpoints
app.get('/api/v1/ai/settings', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/settings', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/ai/settings', (req, res) => proxy(req, res, BACKEND_API))
app.put('/api/v1/ai/settings/switch', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/analyze', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/explain', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/chat', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/ai/patterns', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/ai/agent-patterns', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/agent-patterns', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/ai/agent-patterns/:id', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/ai/suggest-patterns', (req, res) => proxy(req, res, BACKEND_API))

// Detection rules
app.get('/detections', (req, res) => proxy(req, res, BACKEND_API))
app.post('/detections', (req, res) => proxy(req, res, BACKEND_API))
app.get('/detections/:id', (req, res) => proxy(req, res, BACKEND_API))
app.put('/detections/:id', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/detections/:id', (req, res) => proxy(req, res, BACKEND_API))

// Detection findings (IDs contain slashes from file paths — use wildcard routes)
app.get('/api/v1/findings', (req, res) => proxy(req, res, BACKEND_API))
app.get(/^\/api\/v1\/findings\/.+/, (req, res) => proxy(req, res, BACKEND_API))
app.patch(/^\/api\/v1\/findings\/.+/, (req, res) => proxy(req, res, BACKEND_API))
app.post(/^\/api\/v1\/findings\/.*\/explain$/, (req, res) => proxy(req, res, BACKEND_API))
app.post(/^\/api\/v1\/findings\/.*\/resolve-domain$/, (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/findings/reconcile', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/findings/suppressed-summary', (req, res) => proxy(req, res, BACKEND_API))

// Behavioral baselines
app.get('/api/v1/baselines/exclusions', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/baselines/exclusions/:id', (req, res) => proxy(req, res, BACKEND_API))

app.get('/api/v1/baselines/never-baselines', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/baselines/never-baselines', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/baselines/never-baselines/:id', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/baselines/:id/confirm', (req, res) => proxy(req, res, BACKEND_API))

app.delete('/api/v1/baselines/:id', (req, res) => proxy(req, res, BACKEND_API))
app.patch('/api/v1/baselines/:id', (req, res) => proxy(req, res, BACKEND_API))

// Block rules
app.get('/api/v1/block-rules', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/block-rules', (req, res) => proxy(req, res, BACKEND_API))
app.put('/api/v1/block-rules/:id', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/block-rules/:id', (req, res) => proxy(req, res, BACKEND_API))

// Block events
app.get('/api/v1/block-events', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/block-events/stats', (req, res) => proxy(req, res, BACKEND_API))

// Detection exceptions
app.get('/api/v1/exceptions', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/exceptions', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/exceptions/:id', (req, res) => proxy(req, res, BACKEND_API))

// Notifications API (Phase 6)
app.get('/api/v1/notifications', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/notifications/count', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/notifications/read-all', (req, res) => proxy(req, res, BACKEND_API))
app.patch('/api/v1/notifications/:id/read', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/notifications/:id', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/notification-endpoints', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/notification-endpoints', (req, res) => proxy(req, res, BACKEND_API))
app.put('/api/v1/notification-endpoints/:id', (req, res) => proxy(req, res, BACKEND_API))
app.delete('/api/v1/notification-endpoints/:id', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/notification-endpoints/:id/test', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/notification-deliveries', (req, res) => proxy(req, res, BACKEND_API))

// Incidents
app.get('/api/v1/incidents', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/incidents/:id', (req, res) => proxy(req, res, BACKEND_API))
app.patch('/api/v1/incidents/:id', (req, res) => proxy(req, res, BACKEND_API))
app.get('/api/v1/incidents/:id/timeline', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/incidents/:id/explain', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/incidents/:id/ask', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/incidents/:id/ask/stream', (req, res) => proxy(req, res, BACKEND_API))

// Enrichment API (IP → domain/ASN resolution)
app.post('/api/v1/enrich/ip', (req, res) => proxy(req, res, BACKEND_API))
app.post('/api/v1/enrich/ips', (req, res) => proxy(req, res, BACKEND_API))

const BIND_HOST = process.env.BIND_HOST || '0.0.0.0'
const server = app.listen(PORT, BIND_HOST, () => {
  console.log(`✅ Correlic UI proxy running at http://localhost:${PORT}`)
})
server.on('error', (err) => {
  console.error('[ui-proxy] Server error:', err.message)
  process.exit(1)
})

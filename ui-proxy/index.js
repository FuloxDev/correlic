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

    const headers = {
      'Content-Type': 'application/json',
    }

    const upstreamAuth =
      req.headers.authorization || req.headers['x-api-key']
    if (upstreamAuth && String(upstreamAuth).trim() !== '') {
      headers['Authorization'] = String(upstreamAuth)
    } else if (API_KEY && API_KEY.trim() !== '' && API_KEY !== '<RAW_API_KEY>') {
      headers['Authorization'] = API_KEY
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
    const timeoutId = setTimeout(() => controller.abort(), 180_000) // LLM explain/chat can take minutes
    let upstream
    try {
      upstream = await fetch(url, { ...options, signal: controller.signal })
    } finally {
      clearTimeout(timeoutId)
    }

    const contentType = upstream.headers.get('content-type') || 'application/json'
    res.status(upstream.status)
    res.set('Content-Type', contentType)

    // Server-sent events are piped through as they arrive instead of being
    // buffered until the stream ends.
    if (contentType.includes('text/event-stream') && upstream.body) {
      res.set('Cache-Control', 'no-cache')
      res.set('Connection', 'keep-alive')
      res.set('X-Accel-Buffering', 'no')
      res.flushHeaders()
      upstream.body.on('error', () => res.end())
      upstream.body.pipe(res)
      return
    }

    const body = await upstream.text()
    res.send(body)
  } catch (err) {
    console.error('Proxy error:', err.message)
    console.error(err)
    res.status(502).json({ error: 'Upstream request failed' })
  }
}

/**
 * Forwarding. Every backend path family the dashboard uses is forwarded to
 * BACKEND_API as-is; the backend applies its own auth to each route. A prefix
 * rule replaces the old hand-maintained list, which silently dropped new
 * routes (incident chat, Google sign-in) and kept dozens of dead ones.
 */
const FORWARD_PREFIXES = [
  'api/v1', 'auth', 'agents', 'orgs', 'users', 'api-keys', 'agent-tokens',
  'telemetry', 'network', 'ports', 'ai', 'dashboard', 'processes', 'approvals',
  'neo4j', 'query', 'process', 'timeline',
]
const FORWARD_RE = new RegExp(`^/(${FORWARD_PREFIXES.join('|')})(/|$)`)
app.all(FORWARD_RE, (req, res) => proxy(req, res, BACKEND_API))

// Bind to loopback by default: the proxy carries the mTLS client certificate
// and must only be reachable by the dashboard server. Set BIND_HOST=0.0.0.0
// when the dashboard runs in another container on a private network.
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1'
const server = app.listen(PORT, BIND_HOST, () => {
  console.log(`✅ Correlic UI proxy running at http://localhost:${PORT}`)
})
server.on('error', (err) => {
  console.error('[ui-proxy] Server error:', err.message)
  process.exit(1)
})

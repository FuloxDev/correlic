import 'dotenv/config'
import express from 'express'
import fs from 'fs'
import http from 'http'
import https from 'https'
import fetch from 'node-fetch'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'

/**
 * Correlic UI proxy.
 *
 * Browsers cannot present client certificates, so this process holds the
 * backend's mTLS client cert on behalf of the dashboard. It listens on
 * loopback, forwards an allowlisted set of path prefixes to BACKEND_API, and
 * passes through only the headers the dashboard needs. It never adds
 * credentials of its own: a request without an Authorization header is
 * rejected with 401 before anything reaches the backend.
 *
 * LOCAL ONLY - never expose this port publicly.
 */

const {
  PORT = 8788,
  BIND_HOST = '127.0.0.1',
  BACKEND_API,
  MTLS_CA,
  MTLS_CERT,
  MTLS_KEY,
  ALLOWED_ORIGINS,
  UPSTREAM_TIMEOUT_MS,
} = process.env

if (!BACKEND_API) {
  console.error('[ui-proxy] Missing required env var: BACKEND_API')
  process.exit(1)
}

/** Whole-request budget (connect + headers + body) for non-streaming responses. */
const UPSTREAM_TIMEOUT = Number(UPSTREAM_TIMEOUT_MS) > 0 ? Number(UPSTREAM_TIMEOUT_MS) : 180_000
const BODY_LIMIT = '1mb'

const allowedOrigins = ALLOWED_ORIGINS
  ? ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean)
  : ['http://localhost:3000', 'http://localhost:3001']

/**
 * Every backend path family the dashboard uses is forwarded to BACKEND_API
 * as-is; the backend applies its own auth to each route. The check runs on the
 * normalised pathname so `..` segments and encoded dots cannot escape it.
 */
const FORWARD_PREFIXES = [
  'api/v1', 'auth', 'agents', 'orgs', 'users', 'api-keys', 'agent-tokens',
  'telemetry', 'network', 'ports', 'ai', 'dashboard', 'processes', 'approvals',
  'neo4j', 'query', 'process', 'timeline',
]
const FORWARD_RE = new RegExp(`^/(${FORWARD_PREFIXES.join('|')})(/|$)`)
const TRAVERSAL_RE = /(^|\/)\.\.?(\/|$)/

/** Request headers forwarded from the dashboard; everything else is dropped. */
const FORWARD_REQUEST_HEADERS = ['authorization', 'content-type', 'accept']
/** Response headers passed back to the dashboard. */
const FORWARD_RESPONSE_HEADERS = ['content-type', 'content-disposition', 'location', 'x-request-id', 'retry-after']

// ---------------------------------------------------------------------------
// mTLS client identity
// ---------------------------------------------------------------------------
const __dirname = path.dirname(fileURLToPath(import.meta.url))

function mustReadPEM(label, p) {
  if (!p || String(p).trim() === '') {
    console.error(`[ui-proxy] Missing ${label} (env var not set)`)
    process.exit(1)
  }
  const resolved = path.isAbsolute(p) ? p : path.resolve(__dirname, p)
  try {
    return fs.readFileSync(resolved)
  } catch (e) {
    console.error(`[ui-proxy] Failed to read ${label}: ${e?.code || 'error'}`)
    process.exit(1)
  }
}

const httpsAgent = new https.Agent({
  ca: mustReadPEM('MTLS_CA', MTLS_CA),
  cert: mustReadPEM('MTLS_CERT', MTLS_CERT),
  key: mustReadPEM('MTLS_KEY', MTLS_KEY),
  rejectUnauthorized: true, // DO NOT disable
  keepAlive: true,
})

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
const app = express()
app.disable('x-powered-by')
// Errors are always answered by the JSON handler below; Express' own HTML
// error page (which embeds stack traces outside production) is never used.
app.set('env', 'production')

app.use(
  cors({
    origin: (origin, callback) => {
      // Server-to-server calls (the dashboard's Node process, curl) have no Origin.
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true)
      const err = new Error('origin not allowed')
      err.status = 403
      callback(err)
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    optionsSuccessStatus: 204,
    credentials: true,
  })
)

// Liveness of the proxy itself (the backend has its own /health, not forwarded).
app.get('/health', (_req, res) => res.json({ status: 'ok' }))

// Bodies are forwarded byte-for-byte with the Content-Type the client sent.
app.use(express.raw({ type: () => true, limit: BODY_LIMIT }))

app.all(/.*/, (req, res) => {
  let url
  try {
    url = new URL(req.originalUrl, 'http://ui-proxy.local')
  } catch {
    return res.status(400).json({ error: 'bad request' })
  }

  let decodedPath
  try {
    decodedPath = decodeURIComponent(url.pathname)
  } catch {
    return res.status(404).json({ error: 'not found' })
  }
  if (!FORWARD_RE.test(url.pathname) || TRAVERSAL_RE.test(decodedPath)) {
    return res.status(404).json({ error: 'not found' })
  }

  const authorization = req.headers.authorization
  if (!authorization || String(authorization).trim() === '') {
    return res.status(401).json({ error: 'unauthorized' })
  }

  return proxy(req, res, url.pathname + url.search)
})

/**
 * Forward one request to the backend.
 *  - aborts the upstream request as soon as the client goes away;
 *  - enforces UPSTREAM_TIMEOUT over the whole exchange for ordinary responses;
 *  - keeps server-sent event streams open for as long as the client stays.
 */
async function proxy(req, res, target) {
  const url = new URL(target, BACKEND_API)

  const headers = {}
  for (const name of FORWARD_REQUEST_HEADERS) {
    const value = req.headers[name]
    if (value) headers[name] = String(value)
  }

  const controller = new AbortController()
  let timedOut = false
  let timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, UPSTREAM_TIMEOUT)
  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer)
      timer = null
    }
  }

  // `res` closes either when the response finished or when the client
  // disconnected early; only the latter needs the upstream call cancelled.
  res.on('close', () => {
    if (!res.writableFinished) controller.abort()
  })

  const options = {
    method: req.method,
    agent: httpsAgent,
    headers,
    signal: controller.signal,
    redirect: 'manual',
  }
  if (req.method !== 'GET' && req.method !== 'HEAD' && Buffer.isBuffer(req.body) && req.body.length > 0) {
    options.body = req.body
  }

  let upstream
  try {
    upstream = await fetch(url, options)
  } catch (err) {
    clearTimer()
    if (res.writableEnded || res.destroyed) return
    if (timedOut) return res.status(504).json({ error: 'upstream timeout' })
    if (controller.signal.aborted) return res.end() // client went away
    console.error('[ui-proxy] upstream request failed:', err?.code || err?.name || 'error')
    return res.status(502).json({ error: 'Upstream request failed' })
  }

  res.status(upstream.status)
  for (const name of FORWARD_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name)
    if (value) res.set(name, value)
  }

  const contentType = upstream.headers.get('content-type') || ''
  const isEventStream = contentType.includes('text/event-stream')

  if (!upstream.body || upstream.status === 204 || upstream.status === 304) {
    clearTimer()
    return res.end()
  }

  if (isEventStream) {
    // Streams run until the client disconnects; the timeout does not apply.
    clearTimer()
    res.set('Cache-Control', 'no-cache')
    res.set('X-Accel-Buffering', 'no')
    res.flushHeaders()
  }

  upstream.body.on('end', clearTimer)
  upstream.body.on('error', () => {
    clearTimer()
    if (!res.writableEnded) res.end()
  })
  upstream.body.pipe(res)
}

// Anything not handled above (cannot normally happen; defensive).
app.use((_req, res) => res.status(404).json({ error: 'not found' }))

// JSON-only error responses: no HTML, no stack traces, no file paths.
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (res.headersSent) {
    res.end()
    return
  }
  const type = err?.type
  if (type === 'entity.too.large' || err?.status === 413) {
    return res.status(413).json({ error: 'payload too large' })
  }
  if (type === 'entity.parse.failed' || type === 'request.size.invalid' || type === 'encoding.unsupported' || type === 'charset.unsupported') {
    return res.status(400).json({ error: 'bad request body' })
  }
  if (type === 'request.aborted') {
    return res.end()
  }
  if (err?.status === 403) {
    return res.status(403).json({ error: 'origin not allowed' })
  }
  const status = Number.isInteger(err?.status) && err.status >= 400 && err.status < 600 ? err.status : 500
  if (status >= 500) console.error('[ui-proxy] request failed:', err?.code || err?.name || 'error')
  const label = status === 500 ? 'internal error' : (http.STATUS_CODES[status] || 'error').toLowerCase()
  res.status(status).json({ error: label })
})

// Bind to loopback by default: the proxy carries the mTLS client certificate
// and must only be reachable by the dashboard server. Set BIND_HOST=0.0.0.0
// when the dashboard runs in another container on a private network.
const server = app.listen(Number(PORT), BIND_HOST, () => {
  console.log(`[ui-proxy] listening on http://${BIND_HOST}:${PORT} -> ${BACKEND_API}`)
})
server.on('error', (err) => {
  console.error('[ui-proxy] Server error:', err?.code || err?.message || 'error')
  process.exit(1)
})

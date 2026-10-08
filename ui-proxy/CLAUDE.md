# Correlic UI Proxy — Claude Code Context

## Purpose
Small Express 5 service (`index.js`, ESM) that sits between the Next.js dashboard
server and the backend API. Browsers cannot present client certificates, so this
process holds the backend's **mTLS client cert** and makes the HTTPS call on the
dashboard's behalf. It listens on loopback port **8788** and must never be
exposed publicly.

```
Next.js server (/api/proxy/*) ──HTTP──▶ ui-proxy :8788 ──HTTPS + mTLS──▶ backend :8080
```

## What it enforces
- **Prefix allowlist** on the normalised pathname (`new URL(req.originalUrl).pathname`):
  `api/v1, auth, agents, orgs, users, api-keys, agent-tokens, telemetry, network, ports,
  ai, dashboard, processes, approvals, neo4j, query, process, timeline`. Anything else,
  or any `.`/`..` segment after decoding, is a JSON 404.
- **No credentials of its own**: requests without an `Authorization` header get a JSON
  401 (`/health` excepted). The `API_KEY` env var is not read.
- Only `Authorization`, `Content-Type`, `Accept` are forwarded upstream; only
  `Content-Type`, `Content-Disposition`, `Location`, `X-Request-Id`, `Retry-After` come back.
- Bodies are streamed raw (`express.raw`, 1 MB limit → JSON 413) with the original Content-Type.
- Upstream requests are aborted when the client disconnects; ordinary responses have a
  180 s overall budget (JSON 504); `text/event-stream` responses stay open while the client does.
- CORS: only `ALLOWED_ORIGINS` (default `http://localhost:3000`, `http://localhost:3001`);
  a disallowed Origin gets a JSON 403. All errors are JSON (no HTML, no stack traces).

## Environment variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `BACKEND_API` | _(required)_ | Backend base URL, e.g. `https://localhost:8080`. |
| `MTLS_CA`, `MTLS_CERT`, `MTLS_KEY` | _(required)_ | PEM paths for the client identity (relative paths resolve from this directory). |
| `PORT` | `8788` | Listen port. |
| `BIND_HOST` | `127.0.0.1` | Set `0.0.0.0` only when the dashboard runs in another container on a private network. |
| `ALLOWED_ORIGINS` | localhost:3000/3001 | Comma-separated browser origins allowed by CORS. |
| `UPSTREAM_TIMEOUT_MS` | `180000` | Overall budget for non-streaming upstream requests. |

## Running
```bash
npm install
BACKEND_API=https://localhost:8080 MTLS_CA=ca.crt MTLS_CERT=client.crt MTLS_KEY=client.key node index.js
node --check index.js   # syntax check
```

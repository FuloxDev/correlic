# Correlic UI Proxy — Claude Code Context

## Purpose
Thin Node.js HTTPS proxy. Handles TLS termination and routes requests between the browser, the UI (Next.js), and the backend API. Sits in front of both in production.

## Tech Stack
- Node.js, http-proxy (or similar)
- Entry point: `index.js`

## Routing Logic
```
Browser → HTTPS :443 (proxy)
  /api/*         → Backend API (correlic-backend :8080)
  /*             → UI (correlic-ui :3000)
```

## Running
```bash
npm install
node index.js
# or via Docker / docker-compose
```

## Key Files
- `index.js` — all proxy logic lives here (small codebase)
- `package.json` — dependencies

## Notes
- In dev, you can hit the UI directly on :3000 (Next.js handles /api/* proxy internally)
- This proxy is mainly needed in production for unified TLS + routing
- Certificates configured via environment variables or mounted volumes

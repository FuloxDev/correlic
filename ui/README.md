# Correlic UI

Next.js dashboard for the Correlic security platform. It renders findings,
incidents, baselines, the agent activity timeline and settings, and talks to
the backend only through its own `/api/proxy/*` route handler, which forwards
to the local **ui-proxy** (the process that holds the backend's mTLS client
certificate).

## How requests flow

```
browser ──(cookie)──▶ Next.js /api/proxy/* ──(Authorization: Bearer)──▶ ui-proxy :8788 ──(mTLS)──▶ backend :8080
```

* Signing in with a service API key or with email + password
  (`POST /auth/sessions` on the backend) stores the credential in an
  `httpOnly` cookie. There is no automatic login.
* Signing out revokes backend sessions (`DELETE /auth/sessions`) and clears
  the cookie.
* Pages without a session redirect to `/login?from=…`; API calls without one
  get a JSON 401.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `PROXY_BASE_URL` | `http://localhost:8788` | Where the ui-proxy listens. |
| `PORT` | `3001` | Port the dashboard serves on (`npm run dev` / `npm start`). |
| `CORRELIC_API_URL` | _(unset)_ | Optional remote key server used as a fallback when validating API keys. |
| `NEXT_PUBLIC_GOOGLE_CLIENT_ID` | _(unset)_ | Enables the Google sign-in button. |
| `NEXT_ALLOWED_DEV_ORIGINS` | _(unset)_ | Comma-separated extra origins allowed by the dev server. |

## Running

```bash
npm install
npm run dev        # http://localhost:3001 (needs ui-proxy on :8788)
npm run build      # production build (standalone output)
npm start

npm run lint       # eslint
npm run typecheck  # tsc --noEmit
```

The Docker image runs the standalone build with `node server.js`
(see `Dockerfile`).

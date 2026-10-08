# Correlic UI — Claude Code Context

## Purpose
Next.js dashboard for security analysts: findings, incidents (with AI explain/chat),
behavioral baselines, the agent activity timeline and org settings.

## Tech Stack
- Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS v4
- Recharts (charts), Framer Motion (animation), lucide-react (icons), react-markdown
- Fonts are self-hosted at build time via `next/font` (Inter, Space Grotesk, JetBrains Mono, IBM Plex Sans)
- Dev server runs on port **3001**

## Directory Structure
```
ui/
├── app/
│   ├── layout.tsx            # Root layout: fonts, theme/font boot script
│   ├── providers.tsx         # ToastProvider
│   ├── (dashboard)/          # Protected routes + layout (top bar, sidebar drawer, status banner)
│   ├── login/                # Login page (API key or email/password), centered layout
│   ├── auth/                 # reset-password, verify-email (centered layout)
│   └── api/
│       ├── auth/             # login / logout / google route handlers (set the session cookie)
│       └── proxy/[...path]/  # Forwards to ui-proxy with Authorization: Bearer <cookie value>
├── components/               # Dashboard widgets, incidents views, top-bar pieces
├── component/                # Small primitives (Card, Button, Input, ToastProvider)
├── lib/
│   ├── api.ts                # fetchJSON + ApiError; drives the backend status store
│   ├── api-client.ts         # Typed endpoint wrappers
│   ├── backend-status.ts     # "backend unreachable" store + out-of-React toast channel
│   ├── use-polling.ts        # Visibility-aware polling hook
│   ├── appearance.ts         # Theme/font tables shared by boot script and picker
│   └── server/session.ts     # Cookie options, PROXY_BASE, session-token helpers (server only)
└── proxy.ts                  # Route protection (Next 16 "proxy" convention)
```

## Auth model
- Cookie `correlic_session` holds either a service API key or a backend session token (UUID).
- `app/api/proxy/[...path]/route.ts` sends it as `Authorization: Bearer …`; no cookie → 401 JSON.
- `proxy.ts`: `/login`, `/auth/*`, `/api/auth/*` are public; other pages redirect to `/login?from=…`.
- Logout calls backend `DELETE /auth/sessions` when the cookie is a session token, then clears it.
- Never read an `API_KEY` env var here; there is no auto-login.

## Data fetching
- Plain `fetch` through `lib/api.ts`; no React Query.
- `usePolling(fn, ms)` pauses when the tab is hidden. Dashboard default 60 s, NotificationBell 30 s.
- 401 → redirect to login; 403 → "You don't have permission" toast; 0/502/503/504 → BackendStatusBanner.
- The dashboard reads counts from `/dashboard/stats`; it does not fetch the findings list.

## Environment Variables
```
PROXY_BASE_URL=http://localhost:8788      # ui-proxy address (server side)
PORT=3001
CORRELIC_API_URL=                          # optional remote key server fallback
NEXT_PUBLIC_GOOGLE_CLIENT_ID=              # optional Google sign-in
NEXT_ALLOWED_DEV_ORIGINS=                  # optional extra dev origins
```

## Running
```bash
npm install
npm run dev        # :3001
npm run build      # standalone output for Docker
npm run lint
npm run typecheck
```

## Conventions
- Muted text uses the `text-dim` utility (`--foreground-dim`, ≥ 4.5:1 on every theme), not `text-gray-500/600`.
- Icon-only buttons need `aria-label`; `Input`/`Select` wire `label` to the control via `useId`.
- Theme ids live in `lib/appearance.ts`; `data-theme`/`data-font` on `<html>` drive the CSS.

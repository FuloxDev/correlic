# Correlic UI — Claude Code Context

## Purpose
Next.js web frontend for security analysts. Displays real-time event timelines, process trees, alerts, and detection rule management.

## Tech Stack
- Next.js 16 (App Router), React 19, TypeScript
- TailwindCSS, React Query (data fetching), Recharts (visualizations), Framer Motion (animations)
- Auth: session-based (in progress)

## Directory Structure
```
correlic-ui/
├── app/                    # Next.js App Router
│   ├── layout.tsx          # Root layout
│   ├── providers.tsx       # React Query + auth providers
│   ├── (dashboard)/        # Main dashboard routes (protected)
│   ├── login/              # Auth pages
│   └── api/                # Next.js API routes (proxy to backend)
├── components/             # Shared UI components
├── component/              # Feature-specific components
├── lib/                    # Utilities, API client, types
├── proxy.ts                 # Auth proxy (route protection, Next.js 16 convention)
├── next.config.ts
└── package.json
```

## Key Features
- **Event Timeline** — chronological view of telemetry events
- **Process Tree** — D3.js parent-child visualization
- **Recursive File Tree** — nested file access explorer
- **Alert Dashboard** — security alerts management
- **Detection Rules** — configure custom detection logic
- **Search & Filter** — query by process, file, IP, event type

## API Communication
UI talks to backend via `/api/v1/*`. In dev, the UI proxy handles routing.
React Query used for polling (every 5s for new events).

```typescript
// Typical fetch pattern
const { data } = useQuery(['events'], () =>
  fetch('/api/v1/events?limit=100').then(r => r.json())
)
```

## Running
```bash
npm install
npm run dev      # dev server on :3001
npm run build    # production build
npm run lint
```

## Environment Variables
```
NEXT_PUBLIC_API_URL=https://localhost:8080   # backend URL
```

## Key Files
- Root layout: `app/layout.tsx`
- Auth proxy: `proxy.ts`
- API client: `lib/` (look for api.ts or client.ts)
- Dashboard routes: `app/(dashboard)/`
- Components: `components/` and `component/`

## Current State
Basic UI working. In progress (v0.2):
- Alert system UI
- Detection rules management UI
- Interactive process tree (D3.js)
- User authentication (login page exists, full RBAC pending)

## Common Issues
- CORS: handled by ui-proxy in production; in dev, Next.js API routes proxy requests
- Auth: `proxy.ts` protects dashboard routes, redirects to `/login`

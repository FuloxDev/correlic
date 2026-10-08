import { notifyToast, reportBackendReachable, reportBackendUnreachable } from './backend-status'

// Every call goes through the Next.js route handler, which attaches the
// session cookie's credential and forwards to ui-proxy (mTLS holder).
const BASE = '/api/proxy'

export class ApiError extends Error {
  status: number
  body: string

  constructor(status: number, body: string) {
    super(status === 0 ? `Network error: ${body}` : `HTTP ${status}: ${body}`)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

/** Statuses that mean "the backend is down", not "this request was wrong". */
const UNREACHABLE_STATUSES = new Set([0, 502, 503, 504])
const PERMISSION_MESSAGE = "You don't have permission to do that"

let redirectingToLogin = false

function handleFailure(status: number) {
  if (typeof window === 'undefined') return

  if (UNREACHABLE_STATUSES.has(status)) {
    reportBackendUnreachable()
    return
  }

  if (status === 401) {
    if (redirectingToLogin || window.location.pathname.startsWith('/login')) return
    redirectingToLogin = true
    const from = window.location.pathname + window.location.search
    window.location.assign(`/login?from=${encodeURIComponent(from)}`)
    return
  }

  if (status === 403) {
    notifyToast(PERMISSION_MESSAGE, 'error')
  }
}

export function isPermissionError(err: unknown): boolean {
  return err instanceof ApiError && err.status === 403
}

export async function fetchJSON<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  const isGet = !init?.method || init.method === 'GET'

  const headers: HeadersInit = {
    ...(isGet ? {} : { 'Content-Type': 'application/json' }),
    ...(init?.headers ?? {}),
  }

  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, {
      cache: 'no-store',
      credentials: 'include',
      ...init,
      headers,
    })
  } catch (err) {
    handleFailure(0)
    throw new ApiError(0, err instanceof Error ? err.message : 'request failed')
  }

  const text = await res.text()

  if (!res.ok) {
    handleFailure(res.status)
    throw new ApiError(res.status, text)
  }

  reportBackendReachable()

  if (!text) {
    return undefined as T
  }

  try {
    return JSON.parse(text) as T
  } catch {
    throw new Error('Invalid JSON response')
  }
}

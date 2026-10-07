// Use Next.js API route for server-side proxying (avoids CORS and mixed content issues)
// Falls back to direct proxy URL for local development if needed
const BASE = process.env.NEXT_PUBLIC_PROXY_BASE || '/api/proxy'

export class ApiError extends Error {
  status: number
  body: string

  constructor(status: number, body: string) {
    super(`HTTP ${status}: ${body}`)
    this.status = status
    this.body = body
  }
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
  
  const res = await fetch(`${BASE}${path}`, {
    cache: 'no-store',
    credentials: 'include',
    ...init,
    headers,
  })

  const text = await res.text()

  if (!res.ok) {
    // Don't clear localStorage on 403 (forbidden) - that's a permissions issue, not auth
    // Only clear on 401 (unauthorized) which means the API key is invalid
    if (res.status === 401 && typeof window !== 'undefined') {
      console.warn('[fetchJSON] Got 401 Unauthorized - API key may be invalid')
      // Don't auto-clear - let the user handle it
    }
    throw new ApiError(res.status, text)
  }

  if (!text) {
    return undefined as T
  }

  try {
    return JSON.parse(text) as T
  } catch {
    throw new Error('Invalid JSON response')
  }
}

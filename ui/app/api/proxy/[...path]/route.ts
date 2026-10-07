import { NextRequest, NextResponse } from 'next/server'

// Route everything through ui-proxy (it handles routing to correct backend)
const PROXY_BASE = process.env.PROXY_BASE_URL || 'http://localhost:8788'
const SESSION_COOKIE = 'correlic_session'
const EMAIL_COOKIE = 'correlic_user_email'

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, path)
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, path)
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, path)
}

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, path)
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, path)
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-User-Email',
    },
  })
}

async function proxyRequest(request: NextRequest, _pathSegments: string[]) {
  // Extract path from raw URL to preserve URL-encoding (e.g. %2F in finding IDs).
  // Next.js decodes pathSegments and nextUrl.pathname, which breaks IDs containing slashes.
  const rawUrl = request.url
  const proxyPrefix = '/api/proxy'
  const prefixIdx = rawUrl.indexOf(proxyPrefix)
  const afterProxy = prefixIdx >= 0 ? rawUrl.slice(prefixIdx + proxyPrefix.length) : '/' + _pathSegments.join('/')
  // Split off query string — we'll reconstruct it below
  const [rawPath] = afterProxy.split('?', 2)
  const searchParams = request.nextUrl.searchParams.toString()
  // Route everything through ui-proxy (it knows how to route to API vs Telemetry backends)
  const url = `${PROXY_BASE}${rawPath}${searchParams ? '?' + searchParams : ''}`

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  }

  // Forward Authorization header from request, or use fallback from env
  // Next.js headers are case-insensitive, but we check both lowercase and the actual header name
  const authHeader =
    request.headers.get('authorization') ||
    request.headers.get('Authorization') ||
    request.headers.get('x-api-key') ||
    request.headers.get('X-API-Key')
  
  if (authHeader && authHeader.trim() !== '') {
    headers['Authorization'] = authHeader.trim()
  } else {
    const cookieToken = request.cookies.get(SESSION_COOKIE)?.value
    if (cookieToken && cookieToken.trim() !== '') {
      headers['Authorization'] = cookieToken.trim()
    } else {
      // Try multiple env var names for API key
      const apiKey = process.env.API_KEY || process.env.NEXT_PUBLIC_API_KEY
      if (apiKey && apiKey.trim() !== '' && apiKey !== '<RAW_API_KEY>') {
        headers['Authorization'] = apiKey
      } else {
        console.warn('[Next.js Proxy] No API key found in request or environment')
      }
    }
  }

  // Forward X-User-Email header
  const userEmail = request.headers.get('x-user-email') || request.cookies.get(EMAIL_COOKIE)?.value
  if (userEmail) {
    headers['X-User-Email'] = userEmail
  }

  const options: RequestInit = {
    method: request.method,
    headers,
  }

  // Forward request body for methods that typically have one
  if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
    try {
      const body = await request.text()
      if (body) {
        options.body = body
      }
    } catch (e) {
      // No body, continue
    }
  }

  try {
    const response = await fetch(url, options)
    const contentType = response.headers.get('content-type') || 'application/json'

    console.log(`[Next.js Proxy] ${request.method} ${rawPath} -> ${response.status}`)

    // Stream SSE responses unbuffered
    if (contentType.includes('text/event-stream') && response.body) {
      return new NextResponse(response.body as ReadableStream, {
        status: response.status,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',
        },
      })
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return new NextResponse(null, { status: 204 })
    }

    const text = await response.text()
    if (response.status >= 400) {
      console.log(`[Next.js Proxy] Error response body: ${text.substring(0, 200)}`)
    }

    return new NextResponse(text, {
      status: response.status,
      headers: {
        'Content-Type': contentType,
      },
    })
  } catch (error) {
    console.error('[Next.js Proxy] Proxy error:', error)
    return NextResponse.json(
      { error: 'Upstream request failed' },
      { status: 502 }
    )
  }
}

// Removed selectBase - ui-proxy handles routing to correct backend

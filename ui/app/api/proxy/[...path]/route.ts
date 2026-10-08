import { NextRequest, NextResponse } from 'next/server'
import { PROXY_BASE, authorizationHeader, getSessionToken } from '@/lib/server/session'

type RouteContext = { params: Promise<{ path: string[] }> }

export async function GET(request: NextRequest, ctx: RouteContext) {
  return proxyRequest(request, ctx)
}

export async function POST(request: NextRequest, ctx: RouteContext) {
  return proxyRequest(request, ctx)
}

export async function PUT(request: NextRequest, ctx: RouteContext) {
  return proxyRequest(request, ctx)
}

export async function PATCH(request: NextRequest, ctx: RouteContext) {
  return proxyRequest(request, ctx)
}

export async function DELETE(request: NextRequest, ctx: RouteContext) {
  return proxyRequest(request, ctx)
}

/** Upstream response headers the browser is allowed to see. */
const PASSTHROUGH_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'location',
  'x-request-id',
  'retry-after',
]

async function proxyRequest(request: NextRequest, { params }: RouteContext) {
  const token = getSessionToken(request)
  if (!token) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  }

  // Take the path from the raw URL to preserve URL-encoding (e.g. %2F inside
  // finding IDs). Next.js decodes `params` and `nextUrl.pathname`, which would
  // break IDs that contain slashes.
  const { path } = await params
  const prefix = '/api/proxy'
  const rawUrl = request.url
  const prefixIdx = rawUrl.indexOf(prefix + '/')
  const afterPrefix = prefixIdx >= 0 ? rawUrl.slice(prefixIdx + prefix.length) : '/' + path.join('/')
  const rawPath = afterPrefix.split('?', 1)[0]
  const url = `${PROXY_BASE}${rawPath}${request.nextUrl.search}`

  const headers = new Headers()
  headers.set('Authorization', authorizationHeader(token))
  const accept = request.headers.get('accept')
  if (accept) headers.set('Accept', accept)

  const init: RequestInit = {
    method: request.method,
    headers,
    redirect: 'manual',
    signal: request.signal,
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const body = await request.arrayBuffer()
    if (body.byteLength > 0) {
      init.body = body
      headers.set('Content-Type', request.headers.get('content-type') || 'application/json')
    }
  }

  let upstream: Response
  try {
    upstream = await fetch(url, init)
  } catch (error) {
    if (request.signal.aborted) {
      return new NextResponse(null, { status: 499 })
    }
    console.error('[proxy] upstream request failed:', error instanceof Error ? error.message : 'unknown error')
    return NextResponse.json({ error: 'Upstream request failed' }, { status: 502 })
  }

  const responseHeaders = new Headers()
  for (const name of PASSTHROUGH_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name)
    if (value) responseHeaders.set(name, value)
  }
  const contentType = upstream.headers.get('content-type') || ''
  if (contentType.includes('text/event-stream')) {
    responseHeaders.set('Cache-Control', 'no-cache')
    responseHeaders.set('X-Accel-Buffering', 'no')
  }

  const status = upstream.status
  if (status === 204 || status === 304 || !upstream.body) {
    return new NextResponse(null, { status, headers: responseHeaders })
  }

  // Stream the upstream body through unbuffered (SSE and large responses alike).
  return new NextResponse(upstream.body, { status, headers: responseHeaders })
}

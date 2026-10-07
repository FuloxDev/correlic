'use client'

import { useEffect, useRef, useCallback } from 'react'

const DOT_SPACING = 45
const DOT_BASE_RADIUS = 1
const DOT_MAX_RADIUS = 2.8
const DOT_BASE_ALPHA = 0.12
const DOT_MAX_ALPHA = 0.6
const INFLUENCE_RADIUS = 160

const ORB_RADIUS = 280
const ORB_LERP = 0.06

export function InteractiveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const mouseRef = useRef({ x: -1000, y: -1000 })
  const orbRef = useRef({ x: -1000, y: -1000 })
  const rafRef = useRef<number>(0)
  const sizeRef = useRef({ w: 0, h: 0 })

  const draw = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const { w, h } = sizeRef.current
    if (w === 0 || h === 0) {
      rafRef.current = requestAnimationFrame(draw)
      return
    }

    const mouse = mouseRef.current
    const orb = orbRef.current

    // Lerp orb position toward mouse
    orb.x += (mouse.x - orb.x) * ORB_LERP
    orb.y += (mouse.y - orb.y) * ORB_LERP

    ctx.clearRect(0, 0, w, h)

    // ── Gradient orb follower ──
    const orbGrad = ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, ORB_RADIUS)
    orbGrad.addColorStop(0, 'rgba(147, 51, 234, 0.07)')
    orbGrad.addColorStop(0.4, 'rgba(147, 51, 234, 0.03)')
    orbGrad.addColorStop(1, 'rgba(147, 51, 234, 0)')
    ctx.fillStyle = orbGrad
    ctx.fillRect(0, 0, w, h)

    // ── Interactive dot grid ──
    const cols = Math.ceil(w / DOT_SPACING) + 1
    const rows = Math.ceil(h / DOT_SPACING) + 1
    const offsetX = (w - (cols - 1) * DOT_SPACING) / 2
    const offsetY = (h - (rows - 1) * DOT_SPACING) / 2

    // Determine influenced region
    const minCol = Math.max(0, Math.floor((mouse.x - INFLUENCE_RADIUS - offsetX) / DOT_SPACING) - 1)
    const maxCol = Math.min(cols, Math.ceil((mouse.x + INFLUENCE_RADIUS - offsetX) / DOT_SPACING) + 2)
    const minRow = Math.max(0, Math.floor((mouse.y - INFLUENCE_RADIUS - offsetY) / DOT_SPACING) - 1)
    const maxRow = Math.min(rows, Math.ceil((mouse.y + INFLUENCE_RADIUS - offsetY) / DOT_SPACING) + 2)

    // Draw base dots (batched)
    ctx.fillStyle = `rgba(147, 51, 234, ${DOT_BASE_ALPHA})`
    ctx.beginPath()
    for (let row = 0; row < rows; row++) {
      for (let col = 0; col < cols; col++) {
        if (row >= minRow && row < maxRow && col >= minCol && col < maxCol) continue
        const x = offsetX + col * DOT_SPACING
        const y = offsetY + row * DOT_SPACING
        ctx.moveTo(x + DOT_BASE_RADIUS, y)
        ctx.arc(x, y, DOT_BASE_RADIUS, 0, Math.PI * 2)
      }
    }
    ctx.fill()

    // Draw influenced dots
    for (let row = minRow; row < maxRow; row++) {
      for (let col = minCol; col < maxCol; col++) {
        const x = offsetX + col * DOT_SPACING
        const y = offsetY + row * DOT_SPACING
        const dx = mouse.x - x
        const dy = mouse.y - y
        const dist = Math.sqrt(dx * dx + dy * dy)

        if (dist < INFLUENCE_RADIUS) {
          const t = 1 - dist / INFLUENCE_RADIUS
          const ease = t * t
          const radius = DOT_BASE_RADIUS + (DOT_MAX_RADIUS - DOT_BASE_RADIUS) * ease
          const alpha = DOT_BASE_ALPHA + (DOT_MAX_ALPHA - DOT_BASE_ALPHA) * ease

          ctx.fillStyle = `rgba(147, 51, 234, ${alpha})`
          ctx.beginPath()
          ctx.arc(x, y, radius, 0, Math.PI * 2)
          ctx.fill()

          // Connection lines to nearby influenced dots
          if (ease > 0.2) {
            const neighbors = [
              [col + 1, row],
              [col, row + 1],
              [col + 1, row + 1],
            ]
            for (const [nc, nr] of neighbors) {
              if (nc >= cols || nr >= rows) continue
              const nx = offsetX + nc * DOT_SPACING
              const ny = offsetY + nr * DOT_SPACING
              const ndx = mouse.x - nx
              const ndy = mouse.y - ny
              const ndist = Math.sqrt(ndx * ndx + ndy * ndy)
              if (ndist < INFLUENCE_RADIUS) {
                const nt = 1 - ndist / INFLUENCE_RADIUS
                const lineAlpha = Math.min(ease, nt) * 0.25
                ctx.strokeStyle = `rgba(147, 51, 234, ${lineAlpha})`
                ctx.lineWidth = 0.8
                ctx.beginPath()
                ctx.moveTo(x, y)
                ctx.lineTo(nx, ny)
                ctx.stroke()
              }
            }
          }
        } else {
          ctx.fillStyle = `rgba(147, 51, 234, ${DOT_BASE_ALPHA})`
          ctx.beginPath()
          ctx.arc(x, y, DOT_BASE_RADIUS, 0, Math.PI * 2)
          ctx.fill()
        }
      }
    }

    rafRef.current = requestAnimationFrame(draw)
  }, [])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio, 2)
      const w = window.innerWidth
      const h = window.innerHeight
      canvas.width = w * dpr
      canvas.height = h * dpr
      canvas.style.width = `${w}px`
      canvas.style.height = `${h}px`
      const ctx = canvas.getContext('2d')
      if (ctx) ctx.scale(dpr, dpr)
      sizeRef.current = { w, h }
    }

    const handleMouse = (e: MouseEvent) => {
      mouseRef.current.x = e.clientX
      mouseRef.current.y = e.clientY
    }

    resize()
    window.addEventListener('resize', resize)
    window.addEventListener('mousemove', handleMouse, { passive: true })

    rafRef.current = requestAnimationFrame(draw)

    return () => {
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouse)
      cancelAnimationFrame(rafRef.current)
    }
  }, [draw])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none"
      style={{ zIndex: 0 }}
    />
  )
}

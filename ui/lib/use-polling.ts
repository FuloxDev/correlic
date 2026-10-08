'use client'

import { useEffect, useRef } from 'react'

/**
 * Calls `fn` once on mount and then every `intervalMs` while the tab is
 * visible. Polling pauses when the document is hidden and resumes (with an
 * immediate refresh) when it becomes visible again. `intervalMs <= 0` means
 * "initial fetch only". Changing the interval does not trigger another
 * immediate call; manual refreshes should call `fn` directly.
 */
export function usePolling(fn: () => unknown, intervalMs: number, enabled = true) {
  const fnRef = useRef(fn)
  const startedRef = useRef(false)

  useEffect(() => {
    fnRef.current = fn
  }, [fn])

  useEffect(() => {
    if (!enabled) return

    let timer: ReturnType<typeof setInterval> | null = null
    const tick = () => {
      void fnRef.current()
    }
    const start = () => {
      if (timer || intervalMs <= 0) return
      timer = setInterval(tick, intervalMs)
    }
    const stop = () => {
      if (!timer) return
      clearInterval(timer)
      timer = null
    }
    const onVisibility = () => {
      if (document.visibilityState === 'hidden') {
        stop()
      } else if (intervalMs > 0) {
        tick()
        start()
      }
    }

    if (!startedRef.current) {
      startedRef.current = true
      tick()
    }
    if (document.visibilityState !== 'hidden') start()
    document.addEventListener('visibilitychange', onVisibility)

    return () => {
      stop()
      document.removeEventListener('visibilitychange', onVisibility)
    }
  }, [intervalMs, enabled])
}

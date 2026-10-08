import { useSyncExternalStore } from 'react'

/**
 * Tiny client-side store shared between the API client and the UI chrome:
 * whether the backend is currently reachable, plus a channel for toasts that
 * originate outside React (e.g. a 403 inside fetchJSON).
 */

export type ToastKind = 'success' | 'error' | 'info'

type Listener = () => void
type ToastListener = (message: string, kind: ToastKind) => void

let unreachable = false
const listeners = new Set<Listener>()
const toastListeners = new Set<ToastListener>()

function setUnreachable(next: boolean) {
  if (unreachable === next) return
  unreachable = next
  for (const listener of listeners) listener()
}

export function reportBackendUnreachable() {
  setUnreachable(true)
}

export function reportBackendReachable() {
  setUnreachable(false)
}

export function subscribeBackendStatus(listener: Listener): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

export function getBackendUnreachable(): boolean {
  return unreachable
}

export function useBackendUnreachable(): boolean {
  return useSyncExternalStore(subscribeBackendStatus, getBackendUnreachable, () => false)
}

export function subscribeToasts(listener: ToastListener): () => void {
  toastListeners.add(listener)
  return () => {
    toastListeners.delete(listener)
  }
}

export function notifyToast(message: string, kind: ToastKind = 'info') {
  for (const listener of toastListeners) listener(message, kind)
}

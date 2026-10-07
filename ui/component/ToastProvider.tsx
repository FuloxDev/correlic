'use client'

import { createContext, useContext, useState, useCallback, ReactNode } from 'react'

type ToastType = 'success' | 'error' | 'info'

interface Toast {
  id: string
  message: string
  type: ToastType
}

interface ToastContextValue {
  showToast: (message: string, type?: ToastType) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const showToast = useCallback((message: string, type: ToastType = 'info') => {
    const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `toast-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }, [])

  const dismissToast = (id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }

  const getToastStyles = (type: ToastType) => {
    switch (type) {
      case 'success':
        return {
          bg: 'var(--status-closed-bg)',
          border: 'var(--status-closed)',
          icon: (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="var(--status-closed)">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          ),
        }
      case 'error':
        return {
          bg: 'var(--status-open-bg)',
          border: 'var(--status-open)',
          icon: (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="var(--status-open)">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          ),
        }
      default:
        return {
          bg: 'var(--accent-muted)',
          border: 'var(--accent)',
          icon: (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="var(--accent)">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          ),
        }
    }
  }

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 space-y-2">
        {toasts.map(toast => {
          const styles = getToastStyles(toast.type)
          return (
            <div
              key={toast.id}
              className="flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg animate-fade-in min-w-72"
              style={{
                background: 'var(--background-secondary)',
                border: `1px solid ${styles.border}`,
              }}
            >
              <div 
                className="p-1 rounded"
                style={{ background: styles.bg }}
              >
                {styles.icon}
              </div>
              <span 
                className="flex-1 text-sm font-medium"
                style={{ color: 'var(--foreground)' }}
              >
                {toast.message}
              </span>
              <button
                onClick={() => dismissToast(toast.id)}
                className="p-1 rounded transition-colors hover:bg-[var(--background-tertiary)]"
                style={{ color: 'var(--foreground-muted)' }}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

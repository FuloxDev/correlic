'use client'

import { ReactNode, ButtonHTMLAttributes, InputHTMLAttributes, SelectHTMLAttributes } from 'react'

// =============================================================================
// Severity Badge
// =============================================================================
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export function SeverityBadge({ severity }: { severity: string }) {
  const level = severity.toLowerCase() as Severity
  
  const styles: Record<Severity, { bg: string; text: string; border: string }> = {
    critical: { bg: 'var(--critical-bg)', text: 'var(--critical)', border: 'var(--critical)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)', border: 'var(--high)' },
    medium: { bg: 'var(--medium-bg)', text: 'var(--medium)', border: 'var(--medium)' },
    low: { bg: 'var(--low-bg)', text: 'var(--low)', border: 'var(--low)' },
    info: { bg: 'var(--info-bg)', text: 'var(--info)', border: 'var(--info)' },
  }

  const style = styles[level] || styles.info

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase tracking-wide"
      style={{
        background: style.bg,
        color: style.text,
        border: `1px solid ${style.border}`,
      }}
    >
      {level === 'critical' && (
        <span className="w-1.5 h-1.5 rounded-full mr-1.5 animate-pulse-glow" style={{ background: style.text }} />
      )}
      {severity}
    </span>
  )
}

// =============================================================================
// Status Badge
// =============================================================================
type Status = 'open' | 'ack' | 'closed' | 'pending' | 'approved' | 'rejected' | 'delivered' | 'failed' | 'dead'

export function StatusBadge({ status }: { status: string }) {
  const level = status.toLowerCase() as Status
  
  const styles: Record<Status, { bg: string; text: string; border: string }> = {
    open: { bg: 'var(--status-open-bg)', text: 'var(--status-open)', border: 'var(--status-open)' },
    ack: { bg: 'var(--status-ack-bg)', text: 'var(--status-ack)', border: 'var(--status-ack)' },
    closed: { bg: 'var(--status-closed-bg)', text: 'var(--status-closed)', border: 'var(--status-closed)' },
    pending: { bg: 'var(--status-pending-bg)', text: 'var(--status-pending)', border: 'var(--status-pending)' },
    approved: { bg: 'var(--status-closed-bg)', text: 'var(--status-closed)', border: 'var(--status-closed)' },
    rejected: { bg: 'var(--status-open-bg)', text: 'var(--status-open)', border: 'var(--status-open)' },
    delivered: { bg: 'var(--status-closed-bg)', text: 'var(--status-closed)', border: 'var(--status-closed)' },
    failed: { bg: 'var(--status-open-bg)', text: 'var(--status-open)', border: 'var(--status-open)' },
    dead: { bg: 'var(--critical-bg)', text: 'var(--critical)', border: 'var(--critical)' },
  }

  const style = styles[level] || { bg: 'var(--info-bg)', text: 'var(--info)', border: 'var(--info)' }

  return (
    <span
      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize"
      style={{
        background: style.bg,
        color: style.text,
        border: `1px solid ${style.border}`,
      }}
    >
      {status}
    </span>
  )
}

// =============================================================================
// Button
// =============================================================================
type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md' | 'lg'
  children: ReactNode
}

export function Button({ variant = 'secondary', size = 'md', children, className = '', ...props }: ButtonProps) {
  const baseStyles = 'inline-flex items-center justify-center font-medium rounded-lg transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed'
  
  const sizeStyles = {
    sm: 'px-2.5 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-5 py-2.5 text-base',
  }

  const variantStyles: Record<ButtonVariant, string> = {
    primary: 'bg-[var(--accent)] text-[var(--background)] hover:bg-[var(--accent-hover)]',
    secondary: 'bg-[var(--background-tertiary)] text-[var(--foreground)] hover:bg-[var(--border)] border border-[var(--border)]',
    ghost: 'bg-transparent text-[var(--foreground-muted)] hover:bg-[var(--background-tertiary)] hover:text-[var(--foreground)]',
    danger: 'bg-[var(--critical-bg)] text-[var(--critical)] border border-[var(--critical)] hover:bg-[var(--critical)] hover:text-white',
  }

  return (
    <button
      className={`${baseStyles} ${sizeStyles[size]} ${variantStyles[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}

// =============================================================================
// Input
// =============================================================================
interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string
  description?: string
}

export function Input({ label, description, className = '', ...props }: InputProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-xs font-medium" style={{ color: 'var(--foreground-muted)' }}>
          {label}
        </label>
      )}
      <input
        className={`w-full px-3 py-2 rounded-lg text-sm outline-none transition-all ${className}`}
        style={{
          background: 'var(--input-bg)',
          border: '1px solid var(--input-border)',
          color: 'var(--foreground)',
        }}
        onFocus={e => e.currentTarget.style.borderColor = 'var(--input-focus)'}
        onBlur={e => e.currentTarget.style.borderColor = 'var(--input-border)'}
        {...props}
      />
      {description && (
        <p className="text-xs" style={{ color: 'var(--foreground-subtle)' }}>
          {description}
        </p>
      )}
    </div>
  )
}

// =============================================================================
// Select
// =============================================================================
interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string
  options: { value: string; label: string; disabled?: boolean }[]
}

export function Select({ label, options, className = '', ...props }: SelectProps) {
  return (
    <div className="space-y-1.5">
      {label && (
        <label className="block text-xs font-medium" style={{ color: 'var(--foreground-muted)' }}>
          {label}
        </label>
      )}
      <select
        className={`px-3 py-2 rounded-lg text-sm outline-none transition-all cursor-pointer ${className}`}
        style={{
          background: 'var(--input-bg)',
          border: '1px solid var(--input-border)',
          color: 'var(--foreground)',
        }}
        onFocus={e => e.currentTarget.style.borderColor = 'var(--input-focus)'}
        onBlur={e => e.currentTarget.style.borderColor = 'var(--input-border)'}
        {...props}
      >
        {options.map(opt => (
          <option key={opt.value} value={opt.value} disabled={opt.disabled}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  )
}

// =============================================================================
// Card
// =============================================================================
interface CardProps {
  children: ReactNode
  className?: string
  hover?: boolean
}

export function Card({ children, className = '', hover = false }: CardProps) {
  return (
    <div
      className={`rounded-xl ${hover ? 'transition-all duration-150 hover:border-[var(--border-hover)]' : ''} ${className}`}
      style={{
        background: 'var(--background-secondary)',
        border: '1px solid var(--border)',
      }}
    >
      {children}
    </div>
  )
}

// =============================================================================
// Stat Card
// =============================================================================
interface StatCardProps {
  label: string
  value: string | number
  change?: { value: number; label: string }
  icon?: ReactNode
  color?: 'accent' | 'critical' | 'high' | 'medium' | 'success'
}

export function StatCard({ label, value, change, icon, color = 'accent' }: StatCardProps) {
  const colors = {
    accent: { bg: 'var(--accent-muted)', text: 'var(--accent)' },
    critical: { bg: 'var(--critical-bg)', text: 'var(--critical)' },
    high: { bg: 'var(--high-bg)', text: 'var(--high)' },
    medium: { bg: 'var(--medium-bg)', text: 'var(--medium)' },
    success: { bg: 'var(--status-closed-bg)', text: 'var(--status-closed)' },
  }

  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium" style={{ color: 'var(--foreground-muted)' }}>
            {label}
          </p>
          <p className="text-3xl font-bold mt-1" style={{ color: 'var(--foreground)' }}>
            {value}
          </p>
          {change && (
            <p className="text-xs mt-2" style={{ color: change.value >= 0 ? 'var(--status-closed)' : 'var(--critical)' }}>
              {change.value >= 0 ? '↑' : '↓'} {Math.abs(change.value)}% {change.label}
            </p>
          )}
        </div>
        {icon && (
          <div
            className="p-3 rounded-lg"
            style={{ background: colors[color].bg, color: colors[color].text }}
          >
            {icon}
          </div>
        )}
      </div>
    </Card>
  )
}

// =============================================================================
// Table
// =============================================================================
interface Column<T> {
  key: string
  header: string
  render?: (row: T) => ReactNode
  className?: string
}

interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  onRowClick?: (row: T) => void
  getRowKey: (row: T) => string
}

export function Table<T>({ columns, data, onRowClick, getRowKey }: TableProps<T>) {
  return (
    <div 
      className="rounded-xl overflow-hidden"
      style={{ border: '1px solid var(--border)' }}
    >
      <table className="w-full">
        <thead>
          <tr style={{ background: 'var(--background-tertiary)' }}>
            {columns.map(col => (
              <th
                key={col.key}
                className={`px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider ${col.className || ''}`}
                style={{ color: 'var(--foreground-muted)' }}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody style={{ background: 'var(--background-secondary)' }}>
          {data.map((row, idx) => (
            <tr
              key={getRowKey(row)}
              className={`transition-colors ${onRowClick ? 'cursor-pointer hover:bg-[var(--background-tertiary)]' : ''}`}
              style={{ borderTop: idx > 0 ? '1px solid var(--border)' : undefined }}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map(col => (
                <td
                  key={col.key}
                  className={`px-4 py-3 text-sm ${col.className || ''}`}
                  style={{ color: 'var(--foreground)' }}
                >
                  {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// =============================================================================
// Page Header
// =============================================================================
interface PageHeaderProps {
  title: string
  description?: string
  actions?: ReactNode
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="flex items-start justify-between mb-6">
      <div>
        <h1 
          className="text-2xl font-bold"
          style={{ color: 'var(--foreground)' }}
        >
          {title}
        </h1>
        {description && (
          <p 
            className="mt-1 text-sm"
            style={{ color: 'var(--foreground-muted)' }}
          >
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-3">{actions}</div>}
    </div>
  )
}

// =============================================================================
// Filter Bar
// =============================================================================
interface FilterBarProps {
  children: ReactNode
}

export function FilterBar({ children }: FilterBarProps) {
  return (
    <div 
      className="flex flex-wrap items-end gap-4 p-4 rounded-xl mb-6"
      style={{ background: 'var(--background-secondary)', border: '1px solid var(--border)' }}
    >
      {children}
    </div>
  )
}

// =============================================================================
// Toggle Switch
// =============================================================================
interface ToggleProps {
  label?: string
  description?: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}

export function Toggle({ label, description, checked, onChange, disabled = false }: ToggleProps) {
  return (
    <div className="flex items-start gap-3">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 ${
          disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
        }`}
        style={{
          backgroundColor: checked ? 'var(--accent)' : 'var(--background-tertiary)',
        }}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            checked ? 'translate-x-6' : 'translate-x-1'
          }`}
        />
      </button>
      {(label || description) && (
        <div className="flex-1">
          {label && (
            <label className="block text-sm font-medium" style={{ color: 'var(--foreground)' }}>
              {label}
            </label>
          )}
          {description && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--foreground-muted)' }}>
              {description}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// =============================================================================
// Tab Group
// =============================================================================
interface Tab {
  value: string
  label: string
  count?: number
}

interface TabGroupProps {
  tabs: Tab[]
  value: string
  onChange: (value: string) => void
}

export function TabGroup({ tabs, value, onChange }: TabGroupProps) {
  return (
    <div 
      className="inline-flex rounded-lg p-1"
      style={{ background: 'var(--background-tertiary)' }}
    >
      {tabs.map(tab => (
        <button
          key={tab.value}
          className="px-3 py-1.5 text-sm font-medium rounded-md transition-all"
          style={{
            background: value === tab.value ? 'var(--background-secondary)' : 'transparent',
            color: value === tab.value ? 'var(--foreground)' : 'var(--foreground-muted)',
            boxShadow: value === tab.value ? 'var(--shadow-sm)' : 'none',
          }}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span 
              className="ml-2 px-1.5 py-0.5 text-xs rounded"
              style={{ 
                background: value === tab.value ? 'var(--accent-muted)' : 'var(--background-secondary)',
                color: value === tab.value ? 'var(--accent)' : 'var(--foreground-muted)'
              }}
            >
              {tab.count}
            </span>
          )}
        </button>
      ))}
    </div>
  )
}

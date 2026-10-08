/** Minimal centered frame for the login and /auth/* pages (no sidebar, no top bar). */
export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: 'var(--background)' }}
    >
      <div className="w-full max-w-md">{children}</div>
    </div>
  )
}

'use client'

import { useState } from 'react'
import Link from 'next/link'
import { MessageSquare, Check, Star } from 'lucide-react'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { Button } from '@/components/ui/Button'
import { api } from '@/lib/api'

const categories = ['Bug Report', 'Feature Request', 'Detection Rule', 'UX Feedback', 'Other']

const categoryMap: Record<string, string> = {
  'Bug Report': 'bug',
  'Feature Request': 'feature',
  'Detection Rule': 'detection',
  'UX Feedback': 'ux',
  'Other': 'other',
}

export default function FeedbackPage() {
  const [rating, setRating] = useState(0)
  const [hover, setHover] = useState(0)
  const [category, setCategory] = useState('')
  const [subject, setSubject] = useState('')
  const [message, setMessage] = useState('')
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (!rating) {
      setError('Please select a rating')
      return
    }
    if (!category) {
      setError('Please select a category')
      return
    }

    setLoading(true)

    const { error: err } = await api('/feedback', {
      method: 'POST',
      body: {
        rating,
        category: categoryMap[category] || 'other',
        subject,
        message,
        email: email || undefined,
      },
    })

    setLoading(false)

    if (err) {
      setError(err)
      return
    }

    setDone(true)
  }

  return (
    <>
      <Navbar />
      <main className="pt-24 pb-20 min-h-screen">
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background:
              'radial-gradient(ellipse 50% 40% at 50% 30%, rgba(147,51,234,0.04) 0%, transparent 70%)',
          }}
        />
        <div className="max-w-lg mx-auto px-4 relative z-10">

          {/* Header */}
          <div className="text-center mb-10 space-y-2">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-2xl bg-[rgba(147,51,234,0.08)] border border-[rgba(147,51,234,0.15)] mb-3">
              <MessageSquare className="w-5 h-5 text-[#9333ea]" />
            </div>
            <h1
              className="text-3xl font-bold text-[#e8dff5]"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Share Your Feedback
            </h1>
            <p className="text-[#c4b5d9] text-sm">
              Help shape correlic. Every report is reviewed by the team.
            </p>
          </div>

          {done ? (
            <div className="glass-card p-10 flex flex-col items-center gap-4 text-center">
              <div className="w-14 h-14 rounded-full bg-[rgba(0,230,118,0.1)] border border-[rgba(0,230,118,0.2)] flex items-center justify-center">
                <Check className="w-6 h-6 text-[#00e676]" />
              </div>
              <h2
                className="text-xl font-bold text-[#e8dff5]"
                style={{ fontFamily: "'Space Grotesk', sans-serif" }}
              >
                Feedback received!
              </h2>
              <p className="text-sm text-[#c4b5d9]">Thanks — we read every submission.</p>
              <Link href="/">
                <Button variant="outline" size="sm">← Back to home</Button>
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="glass-card p-8 space-y-6">
              {error && (
                <div className="px-4 py-2.5 rounded-xl bg-[rgba(255,59,92,0.08)] border border-[rgba(255,59,92,0.2)] text-sm text-[#ff3b5c]">
                  {error}
                </div>
              )}

              {/* Star rating */}
              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#c4b5d9]">
                  Overall experience
                </label>
                <div className="flex gap-1.5">
                  {[1, 2, 3, 4, 5].map((n) => (
                    <button
                      key={n}
                      type="button"
                      onClick={() => setRating(n)}
                      onMouseEnter={() => setHover(n)}
                      onMouseLeave={() => setHover(0)}
                      className="transition-transform hover:scale-110"
                    >
                      <Star
                        className="w-7 h-7 transition-colors"
                        fill={(hover || rating) >= n ? '#f59e0b' : 'transparent'}
                        stroke={(hover || rating) >= n ? '#f59e0b' : '#6b5a80'}
                      />
                    </button>
                  ))}
                </div>
              </div>

              {/* Category */}
              <div className="space-y-2">
                <label className="block text-xs font-medium text-[#c4b5d9]">Category</label>
                <div className="flex flex-wrap gap-2">
                  {categories.map((c) => (
                    <button
                      key={c}
                      type="button"
                      onClick={() => setCategory(c)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                        category === c
                          ? 'bg-[rgba(147,51,234,0.12)] border-[rgba(147,51,234,0.3)] text-[#9333ea]'
                          : 'border-[rgba(147,51,234,0.08)] text-[#6b5a80] hover:text-[#c4b5d9] hover:border-[rgba(147,51,234,0.15)]'
                      }`}
                    >
                      {c}
                    </button>
                  ))}
                </div>
              </div>

              {/* Subject */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-[#c4b5d9]">Subject</label>
                <input
                  required
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  placeholder="Brief summary…"
                  className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] transition-all"
                />
              </div>

              {/* Message */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-[#c4b5d9]">Message</label>
                <textarea
                  required
                  rows={5}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Describe the issue or idea in detail…"
                  className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] transition-all resize-none"
                />
              </div>

              {/* Email (optional) */}
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-[#c4b5d9]">
                  Email <span className="text-[#6b5a80]">(optional — for follow-up)</span>
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="w-full bg-[#0a0612] border border-[rgba(147,51,234,0.12)] rounded-xl px-4 py-2.5 text-sm text-[#e8dff5] placeholder-[#6b5a80] focus:outline-none focus:border-[rgba(147,51,234,0.4)] focus:ring-1 focus:ring-[rgba(147,51,234,0.2)] transition-all"
                />
              </div>

              <Button
                type="submit"
                variant="primary"
                size="md"
                className="w-full"
                disabled={loading}
              >
                {loading ? (
                  <span className="flex items-center gap-2">
                    <span className="w-4 h-4 border-2 border-[#0a0612] border-t-transparent rounded-full animate-spin" />
                    Sending…
                  </span>
                ) : (
                  <span className="flex items-center gap-2">
                    <MessageSquare className="w-4 h-4" />
                    Send Feedback
                  </span>
                )}
              </Button>
            </form>
          )}
        </div>
      </main>
      <Footer />
    </>
  )
}

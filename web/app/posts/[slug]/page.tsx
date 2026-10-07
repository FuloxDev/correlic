'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import { motion } from 'framer-motion'
import { ArrowLeft, Clock, Calendar, User, ExternalLink } from 'lucide-react'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { Badge } from '@/components/ui/Badge'
import { fetchPostBySlug, type Post } from '@/lib/api'

const typeConfig = {
  video:   { label: 'Video',   variant: 'high'   as const },
  article: { label: 'Article', variant: 'medium' as const },
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001'

function resolveUrl(url: string | null): string | null {
  if (!url) return null
  return url.startsWith('http') ? url : `${API_BASE}${url}`
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return ''
  return new Date(dateStr).toLocaleDateString('en-US', {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    year: 'numeric',
  })
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

export default function PostDetailPage() {
  const params = useParams()
  const slug = params.slug as string
  const [post, setPost] = useState<Post | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchPostBySlug(slug).then((res) => {
      if (res.data) {
        setPost(res.data)
      } else {
        setError(res.error || 'Post not found')
      }
      setLoading(false)
    })
  }, [slug])

  return (
    <>
      <Navbar />
      <main className="pt-32 pb-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          {/* Back link */}
          <Link
            href="/posts"
            className="inline-flex items-center gap-2 text-sm text-[#c4b5d9] hover:text-[#e8dff5] transition-colors mb-8"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Posts
          </Link>

          {loading ? (
            <div className="space-y-6 animate-pulse">
              <div className="h-8 bg-[rgba(147,51,234,0.08)] rounded w-3/4" />
              <div className="aspect-video bg-[#120a24] rounded-2xl" />
              <div className="space-y-3">
                <div className="h-4 bg-[rgba(147,51,234,0.06)] rounded w-full" />
                <div className="h-4 bg-[rgba(147,51,234,0.06)] rounded w-5/6" />
                <div className="h-4 bg-[rgba(147,51,234,0.06)] rounded w-2/3" />
              </div>
            </div>
          ) : error ? (
            <motion.div
              className="text-center py-20"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <p className="text-[#ff3b5c] text-lg mb-2">Post not found</p>
              <p className="text-[#6b5a80]">{error}</p>
            </motion.div>
          ) : post ? (
            <motion.article
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5 }}
            >
              {/* Header */}
              <div className="mb-8">
                <div className="flex items-center gap-3 mb-4">
                  <Badge variant={typeConfig[post.type].variant}>
                    {typeConfig[post.type].label}
                  </Badge>
                </div>

                <h1
                  className="text-3xl sm:text-4xl lg:text-5xl font-bold text-[#e8dff5] mb-4"
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                >
                  {post.title}
                </h1>

                {post.excerpt && (
                  <p className="text-lg text-[#c4b5d9] mb-6">{post.excerpt}</p>
                )}

                <div className="flex flex-wrap items-center gap-4 text-sm text-[#6b5a80]">
                  <span className="flex items-center gap-1.5">
                    <User className="w-4 h-4" />
                    {post.authorName}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Calendar className="w-4 h-4" />
                    {formatDate(post.publishedAt)}
                  </span>
                  {post.type === 'video' && post.mediaDuration && (
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-4 h-4" />
                      {formatDuration(post.mediaDuration)}
                    </span>
                  )}
                </div>
              </div>

              {/* Media */}
              {post.type === 'video' && post.mediaUrl && (
                <div className="rounded-2xl overflow-hidden border border-[rgba(147,51,234,0.25)] mb-10 bg-black shadow-[0_0_40px_rgba(147,51,234,0.1)]">
                  <video
                    src={resolveUrl(post.mediaUrl)!}
                    controls
                    className="w-full"
                    poster={resolveUrl(post.thumbnailUrl) || undefined}
                    preload="metadata"
                  />
                </div>
              )}

              {post.type === 'article' && post.thumbnailUrl && (
                <div className="rounded-2xl overflow-hidden border border-[rgba(147,51,234,0.15)] mb-10">
                  {post.thumbnailUrl.startsWith('http') ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={post.thumbnailUrl}
                      alt={post.title}
                      className="w-full h-auto"
                    />
                  ) : (
                    <Image
                      src={resolveUrl(post.thumbnailUrl)!}
                      alt={post.title}
                      width={1200}
                      height={675}
                      className="w-full h-auto"
                    />
                  )}
                </div>
              )}

              {/* External article link */}
              {post.type === 'article' && post.externalUrl && (
                <a
                  href={post.externalUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center justify-center gap-3 glass-card p-5 rounded-2xl mb-10
                    text-[#9333ea] hover:text-[#a855f7] hover:border-[rgba(147,51,234,0.4)]
                    hover:shadow-[0_0_20px_rgba(147,51,234,0.15)] transition-all group"
                >
                  <ExternalLink className="w-5 h-5" />
                  <span className="text-lg font-semibold" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
                    Read Full Article
                  </span>
                  <ArrowLeft className="w-4 h-4 rotate-180 group-hover:translate-x-1 transition-transform" />
                </a>
              )}

              {/* Inline content (fallback for articles without external URL) */}
              {post.content && !post.externalUrl && (
                <div
                  className="glass-card p-6 sm:p-10 rounded-2xl prose-invert max-w-none
                    [&_h2]:text-2xl [&_h2]:font-bold [&_h2]:text-[#e8dff5] [&_h2]:mt-8 [&_h2]:mb-4
                    [&_h3]:text-xl [&_h3]:font-semibold [&_h3]:text-[#e8dff5] [&_h3]:mt-6 [&_h3]:mb-3
                    [&_p]:text-[#c4b5d9] [&_p]:leading-relaxed [&_p]:mb-4
                    [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:mb-4 [&_ul]:text-[#c4b5d9]
                    [&_ol]:list-decimal [&_ol]:pl-6 [&_ol]:mb-4 [&_ol]:text-[#c4b5d9]
                    [&_li]:mb-1.5
                    [&_a]:text-[#9333ea] [&_a]:underline [&_a]:hover:text-[#a855f7]
                    [&_code]:bg-[rgba(147,51,234,0.1)] [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:rounded [&_code]:text-sm [&_code]:font-mono [&_code]:text-[#c4b5d9]
                    [&_pre]:bg-[#0a0612] [&_pre]:border [&_pre]:border-[rgba(147,51,234,0.1)] [&_pre]:rounded-xl [&_pre]:p-4 [&_pre]:mb-4 [&_pre]:overflow-x-auto
                    [&_blockquote]:border-l-2 [&_blockquote]:border-[#9333ea] [&_blockquote]:pl-4 [&_blockquote]:italic [&_blockquote]:text-[#c4b5d9]
                    [&_strong]:text-[#e8dff5] [&_strong]:font-semibold
                    [&_img]:rounded-xl [&_img]:my-6
                  "
                  style={{ fontFamily: "'Space Grotesk', sans-serif" }}
                  dangerouslySetInnerHTML={{ __html: post.content }}
                />
              )}
            </motion.article>
          ) : null}
        </div>
      </main>
      <Footer />
    </>
  )
}

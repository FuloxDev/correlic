'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowRight, Play, Clock } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { fetchLatestPosts, type Post } from '@/lib/api'

const typeConfig = {
  video:   { label: 'Video',   variant: 'high'   as const },
  article: { label: 'Article', variant: 'medium' as const },
}

function formatDuration(seconds: number): string {
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}:${s.toString().padStart(2, '0')}`
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return ''
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
  })
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001'

function resolveUrl(url: string | null): string | null {
  if (!url) return null
  return url.startsWith('http') ? url : `${API_BASE}${url}`
}

function MarqueeCard({ post }: { post: Post }) {
  const config = typeConfig[post.type]
  const thumbnailSrc = resolveUrl(post.thumbnailUrl)
  const mediaSrc = resolveUrl(post.mediaUrl)
  const isVideo = post.type === 'video'

  return (
    <Link href={`/posts/${post.slug}`} className="block group shrink-0">
      <div className="w-[280px] sm:w-[320px] rounded-2xl border border-[rgba(147,51,234,0.2)] bg-[rgba(18,10,36,0.6)] backdrop-blur-sm overflow-hidden transition-all duration-300 hover:border-[rgba(147,51,234,0.45)] hover:bg-[rgba(18,10,36,0.85)] hover:shadow-[0_0_30px_rgba(147,51,234,0.2)]">
        {/* Thumbnail */}
        <div className="relative aspect-video overflow-hidden bg-[#120a24]">
          {thumbnailSrc ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={thumbnailSrc}
              alt={post.title}
              className="absolute inset-0 w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            />
          ) : isVideo && mediaSrc ? (
            <video
              src={mediaSrc}
              muted
              preload="metadata"
              className="absolute inset-0 w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
            />
          ) : (
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-xl text-[#9333ea] font-bold">
                {post.title.charAt(0)}
              </span>
            </div>
          )}

          {/* Play button overlay for videos */}
          {isVideo && (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-12 h-12 rounded-full bg-[rgba(0,0,0,0.5)] border border-[rgba(255,255,255,0.15)] flex items-center justify-center backdrop-blur-sm transition-all duration-300 group-hover:bg-[rgba(147,51,234,0.6)] group-hover:scale-110 group-hover:shadow-[0_0_25px_rgba(147,51,234,0.4)]">
                <Play className="w-5 h-5 text-white ml-0.5" fill="white" />
              </div>
            </div>
          )}

          {/* Type badge */}
          <div className="absolute top-2.5 left-2.5">
            <Badge variant={config.variant}>{config.label}</Badge>
          </div>

          {/* Duration */}
          {isVideo && post.mediaDuration && (
            <div className="absolute bottom-2.5 right-2.5 flex items-center gap-1 px-2 py-0.5 rounded-md bg-[rgba(0,0,0,0.75)] text-xs text-[#e8dff5] font-mono">
              <Clock className="w-3 h-3" />
              {formatDuration(post.mediaDuration)}
            </div>
          )}
        </div>

        {/* Content */}
        <div className="p-3.5 space-y-1.5">
          <h3
            className="text-sm font-semibold text-[#e8dff5] line-clamp-2 group-hover:text-white transition-colors"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            {post.title}
          </h3>
          {post.excerpt && (
            <p className="text-xs text-[#c4b5d9] line-clamp-2 leading-relaxed">
              {post.excerpt}
            </p>
          )}
          <div className="flex items-center justify-between text-[11px] text-[#6b5a80] pt-0.5">
            <span>{post.authorName}</span>
            <span>{formatDate(post.publishedAt)}</span>
          </div>
        </div>
      </div>
    </Link>
  )
}

export function PostsMarquee() {
  const [posts, setPosts] = useState<Post[]>([])
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    fetchLatestPosts().then((res) => {
      if (res.data?.posts) setPosts(res.data.posts)
      setLoaded(true)
    })
  }, [])

  if (loaded && posts.length === 0) return null

  return (
    <section className="py-20 lg:py-24 relative overflow-hidden">
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: 'radial-gradient(ellipse 60% 40% at 50% 50%, rgba(147,51,234,0.04) 0%, transparent 70%)',
        }}
      />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
        {/* Heading */}
        <motion.div
          className="text-center mb-14"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
        >
          <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
            Latest Updates
          </span>
          <h2
            className="mt-3 text-3xl sm:text-4xl font-bold text-[#e8dff5]"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Posts & Updates
          </h2>
          <p className="mt-4 text-[#c4b5d9] max-w-2xl mx-auto">
            Videos and articles about Correlic — security observability,
            threat detection, and building safer AI infrastructure.
          </p>
        </motion.div>
      </div>

      {/* Marquee container */}
      {posts.length > 0 && (
        <div className="relative">
          <div
            className="absolute left-0 top-0 bottom-0 w-24 sm:w-40 z-10 pointer-events-none"
            style={{ background: 'linear-gradient(90deg, #0a0612 0%, transparent 100%)' }}
          />
          <div
            className="absolute right-0 top-0 bottom-0 w-24 sm:w-40 z-10 pointer-events-none"
            style={{ background: 'linear-gradient(270deg, #0a0612 0%, transparent 100%)' }}
          />

          <div className="marquee-track-posts flex gap-6 py-2">
            {posts.map((post) => (
              <MarqueeCard key={`a-${post.id}`} post={post} />
            ))}
            {posts.map((post) => (
              <MarqueeCard key={`b-${post.id}`} post={post} />
            ))}
          </div>
        </div>
      )}

      {/* View All Posts button */}
      <motion.div
        className="text-center mt-10"
        initial={{ opacity: 0, y: 10 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ delay: 0.3, duration: 0.4 }}
      >
        <Link href="/posts">
          <Button variant="outline" size="lg">
            View All Posts
            <ArrowRight className="w-4 h-4 ml-2" />
          </Button>
        </Link>
      </motion.div>
    </section>
  )
}

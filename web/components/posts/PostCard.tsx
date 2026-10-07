'use client'

import Link from 'next/link'
import { motion } from 'framer-motion'
import { Play, Clock } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import type { Post } from '@/lib/api'

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
    year: 'numeric',
  })
}

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001'

function resolveUrl(url: string | null): string | null {
  if (!url) return null
  return url.startsWith('http') ? url : `${API_BASE}${url}`
}

interface PostCardProps {
  post: Post
  index?: number
  compact?: boolean
}

export function PostCard({ post, index = 0, compact = false }: PostCardProps) {
  const config = typeConfig[post.type]
  const thumbnailSrc = resolveUrl(post.thumbnailUrl)
  const mediaSrc = resolveUrl(post.mediaUrl)
  const isVideo = post.type === 'video'

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.4, delay: index * 0.08 }}
    >
      <Link href={`/posts/${post.slug}`} className="block group">
        <div
          className={`
            rounded-2xl border border-[rgba(147,51,234,0.15)] bg-[rgba(18,10,36,0.7)]
            backdrop-blur-sm overflow-hidden transition-all duration-300
            hover:border-[rgba(147,51,234,0.4)]
            hover:shadow-[0_0_30px_rgba(147,51,234,0.15),inset_0_0_20px_rgba(147,51,234,0.04)]
            hover:bg-[rgba(18,10,36,0.9)]
            group-hover:scale-[1.02]
            ${compact ? 'w-[300px] sm:w-[320px] shrink-0' : ''}
          `}
        >
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
                <span className="text-2xl text-[#9333ea] font-bold">
                  {post.title.charAt(0)}
                </span>
              </div>
            )}

            {/* Play button overlay for videos */}
            {isVideo && (
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-14 h-14 rounded-full bg-[rgba(0,0,0,0.5)] border border-[rgba(255,255,255,0.15)] flex items-center justify-center backdrop-blur-sm transition-all duration-300 group-hover:bg-[rgba(147,51,234,0.6)] group-hover:scale-110 group-hover:shadow-[0_0_30px_rgba(147,51,234,0.4)]">
                  <Play className="w-6 h-6 text-white ml-0.5" fill="white" />
                </div>
              </div>
            )}

            {/* Type badge overlay */}
            <div className="absolute top-3 left-3">
              <Badge variant={config.variant}>
                {config.label}
              </Badge>
            </div>

            {/* Video duration overlay */}
            {isVideo && post.mediaDuration && (
              <div className="absolute bottom-3 right-3 flex items-center gap-1 px-2 py-0.5 rounded-md bg-[rgba(0,0,0,0.75)] text-xs text-[#e8dff5] font-mono">
                <Clock className="w-3 h-3" />
                {formatDuration(post.mediaDuration)}
              </div>
            )}
          </div>

          {/* Content */}
          <div className="p-4 space-y-2">
            <h3
              className="text-base font-semibold text-[#e8dff5] line-clamp-2 group-hover:text-white transition-colors"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              {post.title}
            </h3>

            {post.excerpt && (
              <p className="text-sm text-[#c4b5d9] line-clamp-2 leading-relaxed">
                {post.excerpt}
              </p>
            )}

            <div className="flex items-center justify-between text-xs text-[#6b5a80] pt-1">
              <span>{post.authorName}</span>
              <span>{formatDate(post.publishedAt)}</span>
            </div>
          </div>
        </div>
      </Link>
    </motion.div>
  )
}

'use client'

import { useEffect, useState, Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { PostCard } from '@/components/posts/PostCard'
import { PostFilters } from '@/components/posts/PostFilters'
import { fetchPosts, type Post } from '@/lib/api'

function PostsContent() {
  const searchParams = useSearchParams()
  const type = searchParams.get('type') || undefined
  const pageParam = searchParams.get('page')
  const currentPage = pageParam ? parseInt(pageParam, 10) : 1

  const [posts, setPosts] = useState<Post[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const limit = 12

  useEffect(() => {
    setLoading(true)
    fetchPosts({ type, page: currentPage, limit }).then((res) => {
      if (res.data) {
        setPosts(res.data.posts)
        setTotal(res.data.total)
      }
      setLoading(false)
    })
  }, [type, currentPage])

  const totalPages = Math.ceil(total / limit)

  return (
    <>
      {/* Filters */}
      <div className="mb-10">
        <PostFilters />
      </div>

      {/* Posts Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="rounded-2xl border border-[rgba(147,51,234,0.1)] bg-[rgba(18,10,36,0.5)] animate-pulse"
            >
              <div className="aspect-video bg-[#120a24] rounded-t-2xl" />
              <div className="p-4 space-y-3">
                <div className="h-4 bg-[rgba(147,51,234,0.08)] rounded w-3/4" />
                <div className="h-3 bg-[rgba(147,51,234,0.06)] rounded w-full" />
                <div className="h-3 bg-[rgba(147,51,234,0.06)] rounded w-1/2" />
              </div>
            </div>
          ))}
        </div>
      ) : posts.length === 0 ? (
        <motion.div
          className="text-center py-20"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <p className="text-[#6b5a80] text-lg">No posts found.</p>
          <p className="text-[#6b5a80] text-sm mt-2">Check back later for new content.</p>
        </motion.div>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {posts.map((post, i) => (
              <PostCard key={post.id} post={post} index={i} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 mt-12">
              {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                <a
                  key={page}
                  href={`/posts?${new URLSearchParams({
                    ...(type ? { type } : {}),
                    ...(page > 1 ? { page: String(page) } : {}),
                  }).toString()}`}
                  className={`
                    w-10 h-10 rounded-lg flex items-center justify-center text-sm font-medium
                    transition-all duration-200 border
                    ${page === currentPage
                      ? 'bg-[rgba(147,51,234,0.15)] border-[#9333ea] text-[#e8dff5]'
                      : 'border-[rgba(147,51,234,0.1)] text-[#c4b5d9] hover:border-[rgba(147,51,234,0.3)] hover:text-[#e8dff5]'
                    }
                  `}
                >
                  {page}
                </a>
              ))}
            </div>
          )}
        </>
      )}
    </>
  )
}

export default function PostsPage() {
  return (
    <>
      <Navbar />
      <main className="pt-32 pb-20 relative">
        {/* Background glow */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background: 'radial-gradient(ellipse 50% 30% at 50% 20%, rgba(147,51,234,0.06) 0%, transparent 70%)',
          }}
        />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
          {/* Header */}
          <motion.div
            className="mb-12"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <span className="text-xs font-semibold text-[#9333ea] uppercase tracking-widest">
              Content & Updates
            </span>
            <h1
              className="mt-3 text-4xl sm:text-5xl font-bold text-[#e8dff5]"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Posts
            </h1>
            <p className="mt-4 text-[#c4b5d9] max-w-2xl text-lg">
              Videos and articles about Correlic and the future of AI
              security observability.
            </p>
          </motion.div>

          <Suspense fallback={null}>
            <PostsContent />
          </Suspense>
        </div>
      </main>
      <Footer />
    </>
  )
}

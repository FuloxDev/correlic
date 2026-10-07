'use client'

import { useSearchParams, useRouter } from 'next/navigation'

const filters = [
  { label: 'All',      value: '' },
  { label: 'Videos',   value: 'video' },
  { label: 'Articles', value: 'article' },
]

export function PostFilters() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const activeType = searchParams.get('type') || ''

  function setType(type: string) {
    const params = new URLSearchParams(searchParams.toString())
    if (type) {
      params.set('type', type)
    } else {
      params.delete('type')
    }
    params.delete('page')
    router.push(`/posts?${params.toString()}`)
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      {filters.map((f) => {
        const isActive = activeType === f.value
        return (
          <button
            key={f.value}
            onClick={() => setType(f.value)}
            className={`
              px-4 py-2 rounded-full text-sm font-medium transition-all duration-200
              border
              ${isActive
                ? 'bg-[rgba(147,51,234,0.15)] border-[#9333ea] text-[#e8dff5] shadow-[0_0_12px_rgba(147,51,234,0.2)]'
                : 'bg-transparent border-[rgba(147,51,234,0.12)] text-[#c4b5d9] hover:border-[rgba(147,51,234,0.3)] hover:text-[#e8dff5]'
              }
            `}
          >
            {f.label}
          </button>
        )
      })}
    </div>
  )
}

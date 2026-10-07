'use client'

import { cn } from '@/lib/utils'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[0.625rem] text-sm font-semibold transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#9333ea] focus-visible:ring-offset-2 focus-visible:ring-offset-[#0a0612] disabled:pointer-events-none disabled:opacity-40 cursor-pointer',
  {
    variants: {
      variant: {
        primary:
          'bg-[#9333ea] text-[#e8dff5] hover:bg-[#7e22ce] shadow-[0_0_20px_rgba(147,51,234,0.3)] hover:shadow-[0_0_30px_rgba(147,51,234,0.5)]',
        outline:
          'border border-[rgba(147,51,234,0.3)] text-[#9333ea] hover:bg-[rgba(147,51,234,0.08)] hover:border-[rgba(147,51,234,0.5)]',
        ghost:
          'text-[#c4b5d9] hover:text-[#e8dff5] hover:bg-[rgba(147,51,234,0.06)]',
        destructive:
          'bg-[rgba(255,59,92,0.12)] border border-[rgba(255,59,92,0.3)] text-[#ff3b5c] hover:bg-[rgba(255,59,92,0.2)]',
        surface:
          'bg-[#120a24] border border-[rgba(147,51,234,0.10)] text-[#e8dff5] hover:border-[rgba(147,51,234,0.25)] hover:bg-[#1a0e35]',
      },
      size: {
        sm: 'h-8 px-3 text-xs',
        md: 'h-10 px-5',
        lg: 'h-12 px-7 text-base',
        xl: 'h-14 px-9 text-lg',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'primary',
      size: 'md',
    },
  }
)

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

export function Button({ className, variant, size, asChild = false, ...props }: ButtonProps) {
  const Comp = asChild ? Slot : 'button'
  return <Comp className={cn(buttonVariants({ variant, size, className }))} {...props} />
}

'use client'

import { useEffect, useRef } from 'react'
import { useMotionValue, useSpring, useTransform, motion } from 'framer-motion'

interface AnimatedNumberProps {
    value: number
    duration?: number
    format?: (n: number) => string
    className?: string
}

export default function AnimatedNumber({
    value,
    duration = 1,
    format = (n) => Math.round(n).toLocaleString(),
    className,
}: AnimatedNumberProps) {
    const motionValue = useMotionValue(0)
    const spring = useSpring(motionValue, {
        stiffness: 100,
        damping: 30,
        duration: duration * 1000,
    })
    const display = useTransform(spring, (v) => format(v))
    const ref = useRef<HTMLSpanElement>(null)

    useEffect(() => {
        motionValue.set(value)
    }, [value, motionValue])

    useEffect(() => {
        const unsubscribe = display.on('change', (v) => {
            if (ref.current) {
                ref.current.textContent = v
            }
        })
        return unsubscribe
    }, [display])

    return <span ref={ref} className={className}>{format(0)}</span>
}

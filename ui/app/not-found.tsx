import Link from 'next/link'
import { Shield, ArrowLeft } from 'lucide-react'

export default function NotFound() {
    return (
        <div className="min-h-screen bg-gradient-to-br from-[#0a0a1a] via-[#0f0f2a] to-[#0a0a1a] text-white flex items-center justify-center">
            <div className="text-center space-y-6">
                <Shield className="w-16 h-16 text-orange-500/50 mx-auto" />
                <h1 className="text-6xl font-bold text-gray-300">404</h1>
                <p className="text-gray-500 text-lg">Page not found</p>
                <Link
                    href="/"
                    className="inline-flex items-center gap-2 px-4 py-2 bg-orange-500/10 border border-orange-500/30 rounded-lg text-orange-400 hover:bg-orange-500/20 transition-all"
                >
                    <ArrowLeft className="w-4 h-4" />
                    Back to Dashboard
                </Link>
            </div>
        </div>
    )
}

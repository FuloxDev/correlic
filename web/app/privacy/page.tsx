import { Metadata } from 'next'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'

export const metadata: Metadata = {
  title: 'Privacy Policy — Correlic',
  description: 'Correlic privacy policy — how we handle your data.',
}

export default function PrivacyPage() {
  return (
    <>
      <Navbar />
      <main className="min-h-screen pt-32 pb-20">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
          <h1
            className="text-3xl sm:text-4xl font-bold text-[#e8dff5] mb-8"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Privacy Policy
          </h1>

          <div className="space-y-6 text-[#c4b5d9] leading-relaxed text-sm">
            <p className="text-base text-[#e8dff5] font-medium">
              Last updated: April 2026
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Our Commitment</h2>
            <p>
              Correlic is a security monitoring tool built on a core principle: <span className="text-[#e8dff5] font-medium">your data stays on your infrastructure</span>.
              The Correlic agent and backend run entirely on your own machines. No telemetry, no event data, and no agent activity ever leaves your environment.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">What We Collect</h2>
            <p>
              When you register for early access on this website, we collect your name, email address, company name, and use case.
              This information is used solely to manage your account and communicate with you about your access.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">What We Don&apos;t Collect</h2>
            <p>
              The Correlic agent does not send any data to Correlic servers. All telemetry, events, findings, and incidents
              are stored locally on your infrastructure. We have no access to your security data.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Third-Party Services</h2>
            <p>
              This website may use basic analytics to understand site traffic. We do not sell, share, or trade your personal information
              with third parties for marketing purposes.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Contact</h2>
            <p>
              Questions about this policy? Reach us at{' '}
              <a href="mailto:hello@correlic.com" className="text-[#9333ea] hover:text-[#a855f7] transition-colors">
                hello@correlic.com
              </a>.
            </p>
          </div>
        </div>
      </main>
      <Footer />
    </>
  )
}

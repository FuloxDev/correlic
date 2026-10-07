import { Metadata } from 'next'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'

export const metadata: Metadata = {
  title: 'Terms of Service — Correlic',
  description: 'Correlic terms of service.',
}

export default function TermsPage() {
  return (
    <>
      <Navbar />
      <main className="min-h-screen pt-32 pb-20">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
          <h1
            className="text-3xl sm:text-4xl font-bold text-[#e8dff5] mb-8"
            style={{ fontFamily: "'Space Grotesk', sans-serif" }}
          >
            Terms of Service
          </h1>

          <div className="space-y-6 text-[#c4b5d9] leading-relaxed text-sm">
            <p className="text-base text-[#e8dff5] font-medium">
              Last updated: April 2026
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Acceptance of Terms</h2>
            <p>
              By accessing or using Correlic&apos;s website and services, you agree to be bound by these Terms of Service.
              If you do not agree, please do not use our services.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Description of Service</h2>
            <p>
              Correlic provides kernel-level security monitoring software for AI coding agents. The service includes
              an agent that runs on your infrastructure, a backend server, and a web dashboard. All components are
              self-hosted on your own machines.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Your Responsibilities</h2>
            <p>
              You are responsible for maintaining the security of your account credentials and API keys.
              You agree to use Correlic only for lawful purposes and in accordance with applicable laws and regulations.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Intellectual Property</h2>
            <p>
              Correlic and its original content, features, and functionality are owned by Correlic and are protected
              by international copyright, trademark, and other intellectual property laws.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Limitation of Liability</h2>
            <p>
              Correlic is provided &quot;as is&quot; without warranty of any kind. In no event shall Correlic be liable for
              any indirect, incidental, special, consequential, or punitive damages arising from your use of the service.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Changes to Terms</h2>
            <p>
              We reserve the right to modify these terms at any time. We will notify users of significant changes
              via email or through the service.
            </p>

            <h2 className="text-xl font-semibold text-[#e8dff5] pt-4">Contact</h2>
            <p>
              Questions about these terms? Reach us at{' '}
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

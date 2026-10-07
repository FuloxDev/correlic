import type { Metadata } from 'next'
import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { AboutSection } from '@/components/about/AboutSection'

export const metadata: Metadata = {
  title: 'About — Correlic',
  description: 'Learn about Correlic — our mission to make AI agent security accessible to every team.',
}

export default function AboutPage() {
  return (
    <>
      <Navbar />
      <main className="pt-16">
        <AboutSection />
      </main>
      <Footer />
    </>
  )
}

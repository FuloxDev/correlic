import { Navbar } from '@/components/nav/Navbar'
import { Footer } from '@/components/footer/Footer'
import { ArchHero } from '@/components/architecture/ArchHero'
import { ScrollJourney } from '@/components/architecture/ScrollJourney'

export const metadata = {
  title: 'How It Works — correlic',
  description:
    'See how correlic monitors AI agent activity from kernel collection through AI-powered incident analysis.',
}

export default function HowItWorksPage() {
  return (
    <>
      <Navbar />
      <main>
        <ArchHero />
        <ScrollJourney />
      </main>
      <Footer />
    </>
  )
}

import { Navbar } from '@/components/nav/Navbar'
import { Hero } from '@/components/hero/Hero'
import { AgentMarquee } from '@/components/agents/AgentMarquee'
import { TrustTicker } from '@/components/home/TrustTicker'
import { QuickHowItWorks } from '@/components/home/QuickHowItWorks'
import { WhoIsThisFor } from '@/components/home/WhoIsThisFor'
import { PostsMarquee } from '@/components/posts/PostsMarquee'
import { FeatureGrid } from '@/components/features/FeatureGrid'
import { DownloadSection } from '@/components/download/DownloadSection'
import { ClosingCTA } from '@/components/home/ClosingCTA'
import { Footer } from '@/components/footer/Footer'

export default function HomePage() {
  return (
    <>
      <Navbar />
      <TrustTicker />
      <main>
        <Hero />
        <AgentMarquee />
        <QuickHowItWorks />
        <WhoIsThisFor />
        <FeatureGrid />
        <DownloadSection />
        <ClosingCTA />
        <PostsMarquee />
      </main>
      <Footer />
    </>
  )
}

export interface OgMetadata {
  title: string | null;
  description: string | null;
  image: string | null;
  siteName: string | null;
  author: string | null;
}

function extractMeta(html: string, property: string): string | null {
  // Match both property="og:X" and name="X" patterns
  const patterns = [
    new RegExp(`<meta[^>]+(?:property|name)=["']${property}["'][^>]+content=["']([^"']+)["']`, "i"),
    new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']${property}["']`, "i"),
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match?.[1]) return match[1];
  }
  return null;
}

function extractTitle(html: string): string | null {
  const match = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match?.[1]?.trim() || null;
}

export async function scrapeOgMetadata(url: string): Promise<OgMetadata> {
  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      Accept: "text/html,application/xhtml+xml",
    },
    redirect: "follow",
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch URL: ${res.status}`);
  }

  const html = await res.text();

  return {
    title: extractMeta(html, "og:title") || extractMeta(html, "twitter:title") || extractTitle(html),
    description: extractMeta(html, "og:description") || extractMeta(html, "description") || extractMeta(html, "twitter:description"),
    image: extractMeta(html, "og:image") || extractMeta(html, "twitter:image"),
    siteName: extractMeta(html, "og:site_name"),
    author: extractMeta(html, "article:author") || extractMeta(html, "author"),
  };
}

/** Theme and font options shared by the root layout boot script and the picker. */

export const THEME_STORAGE_KEY = 'correlic-theme'
export const FONT_STORAGE_KEY = 'correlic-font'

export const themes = [
  { id: 'cyber-grid', label: 'Cyber', color: '#00d4ff' },
  { id: 'dark-forge', label: 'Forge', color: '#f59e0b' },
  { id: 'neon-ops', label: 'Neon', color: '#22c55e' },
  { id: 'correlic-purple', label: 'Purple', color: '#9333ea' },
] as const

export type ThemeId = (typeof themes)[number]['id']
export const DEFAULT_THEME: ThemeId = 'cyber-grid'

/** `slug` is the value of `data-font` on <html>; globals.css maps it to a next/font variable. */
export const fonts = [
  { id: 'Inter', label: 'Inter', slug: 'inter' },
  { id: 'Space Grotesk', label: 'Space Grotesk', slug: 'space-grotesk' },
  { id: 'JetBrains Mono', label: 'JetBrains Mono', slug: 'jetbrains-mono' },
  { id: 'IBM Plex Sans', label: 'IBM Plex Sans', slug: 'ibm-plex-sans' },
] as const

export type FontId = (typeof fonts)[number]['id']
export const DEFAULT_FONT: FontId = 'Inter'

export function isThemeId(value: unknown): value is ThemeId {
  return themes.some(t => t.id === value)
}

export function isFontId(value: unknown): value is FontId {
  return fonts.some(f => f.id === value)
}

export function fontSlug(id: FontId): string {
  return fonts.find(f => f.id === id)?.slug ?? fonts[0].slug
}

export function readStoredTheme(): ThemeId {
  if (typeof window === 'undefined') return DEFAULT_THEME
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY)
    return isThemeId(stored) ? stored : DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

export function readStoredFont(): FontId {
  if (typeof window === 'undefined') return DEFAULT_FONT
  try {
    const stored = window.localStorage.getItem(FONT_STORAGE_KEY)
    return isFontId(stored) ? stored : DEFAULT_FONT
  } catch {
    return DEFAULT_FONT
  }
}

export function applyTheme(id: ThemeId) {
  document.documentElement.setAttribute('data-theme', id)
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, id)
  } catch {
    // storage unavailable (private mode); the attribute still applies for this page
  }
}

export function applyFont(id: FontId) {
  document.documentElement.setAttribute('data-font', fontSlug(id))
  try {
    window.localStorage.setItem(FONT_STORAGE_KEY, id)
  } catch {
    // storage unavailable
  }
}

/**
 * Inline script for <head>: applies the stored theme/font before first paint so
 * there is no flash. Built from the same tables as the picker so they agree.
 */
export function appearanceBootScript(): string {
  const themeIds = JSON.stringify(themes.map(t => t.id))
  const fontMap = JSON.stringify(Object.fromEntries(fonts.map(f => [f.id, f.slug])))
  return `(function(){try{var themes=${themeIds};var t=localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});if(themes.indexOf(t)<0)t=${JSON.stringify(DEFAULT_THEME)};document.documentElement.setAttribute('data-theme',t);var fonts=${fontMap};var f=localStorage.getItem(${JSON.stringify(FONT_STORAGE_KEY)});document.documentElement.setAttribute('data-font',fonts[f]||${JSON.stringify(fontSlug(DEFAULT_FONT))});}catch(e){}})();`
}

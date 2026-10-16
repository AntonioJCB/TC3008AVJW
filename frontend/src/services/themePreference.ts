export type Theme = 'dark' | 'light'

const key = 'baxtersec.theme'

export function getThemePreference(): Theme {
  try { return localStorage.getItem(key) === 'light' ? 'light' : 'dark' } catch { return 'dark' }
}

export function saveThemePreference(theme: Theme): void {
  try { localStorage.setItem(key, theme) } catch { /* Theme still works until reload. */ }
}

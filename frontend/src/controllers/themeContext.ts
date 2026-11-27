import { createContext } from 'react'
import type { Theme } from '../services/themePreference'

export interface ThemeContextValue {
  theme: Theme
  saving: boolean
  error: string | null
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

export const ThemeContext = createContext<ThemeContextValue | null>(null)

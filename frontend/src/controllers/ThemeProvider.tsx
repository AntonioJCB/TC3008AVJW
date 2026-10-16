import { useEffect, useState, type ReactNode } from 'react'
import { ThemeContext } from './themeContext'
import { getThemePreference, saveThemePreference, type Theme } from '../services/themePreference'

export default function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(getThemePreference)

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    saveThemePreference(theme)
  }, [theme])

  return (
    <ThemeContext.Provider value={{
      theme,
      setTheme,
      toggleTheme: () => setTheme((current) => current === 'dark' ? 'light' : 'dark'),
    }}>
      {children}
    </ThemeContext.Provider>
  )
}

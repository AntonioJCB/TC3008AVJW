import { useEffect, type ReactNode } from 'react'
import { ThemeContext } from './themeContext'
import { useAuth } from './useAuth'

export default function ThemeProvider({ children }: { children: ReactNode }) {
  const { theme, themeSaving, themeError, setThemePreference } = useAuth()

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
  }, [theme])

  return (
    <ThemeContext.Provider value={{
      theme,
      saving: themeSaving,
      error: themeError,
      setTheme: (selected) => { void setThemePreference(selected) },
      toggleTheme: () => { void setThemePreference(theme === 'dark' ? 'light' : 'dark') },
    }}>
      {children}
    </ThemeContext.Provider>
  )
}

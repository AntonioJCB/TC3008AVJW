import { CircleHelp } from 'lucide-react'
import { useTheme } from '../../../../controllers/useTheme'
import ThemeOption from './components/ThemeOption'

export default function SettingsScreen() {
  const { theme, setTheme } = useTheme()
  return (
    <section className="content-card simple-section" aria-labelledby="settings-title">
      <div className="eyebrow">PREFERENCIAS</div><h2 id="settings-title">Apariencia</h2><p>Elige cómo se ve el panel. El login permanece en modo oscuro.</p>
      <div className="theme-choice" role="group" aria-label="Tema de la interfaz">
        <ThemeOption theme="dark" selected={theme === 'dark'} onSelect={() => setTheme('dark')} />
        <ThemeOption theme="light" selected={theme === 'light'} onSelect={() => setTheme('light')} />
      </div>
      <div className="settings-note"><CircleHelp size={17} />Esta preferencia se guarda en el navegador.</div>
    </section>
  )
}

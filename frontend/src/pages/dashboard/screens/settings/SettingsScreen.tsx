import { CircleHelp } from 'lucide-react'
import { useTheme } from '../../../../controllers/useTheme'
import InfoTip from '../../components/InfoTip'
import ThemeOption from './components/ThemeOption'

export default function SettingsScreen() {
  const { theme, setTheme, saving, error } = useTheme()
  return (
    <section className="content-card simple-section settings-card" aria-labelledby="settings-title">
      <div className="eyebrow">APARIENCIA</div><div className="portal-info-heading"><h2 id="settings-title">Tema del portal</h2><InfoTip label="tema del portal" text="Elige cómo se ve el panel. El login permanece en modo oscuro." /></div>
      <div className="theme-choice" role="group" aria-label="Tema de la interfaz">
        <ThemeOption theme="dark" selected={theme === 'dark'} disabled={saving} onSelect={() => setTheme('dark')} />
        <ThemeOption theme="light" selected={theme === 'light'} disabled={saving} onSelect={() => setTheme('light')} />
      </div>
      <div className="settings-note" role="status"><CircleHelp size={17} />{saving ? 'Guardando preferencia…' : 'Esta preferencia se guarda en tu cuenta.'}</div>
      {error && <p className="client-error" role="alert">{error}</p>}
    </section>
  )
}

import type { Theme } from '../../../../../services/themePreference'

export default function ThemeOption({ theme, selected, onSelect }: { theme: Theme; selected: boolean; onSelect: () => void }) {
  return <button type="button" className={selected ? 'selected' : ''} onClick={onSelect} aria-pressed={selected}><span className={`theme-preview ${theme === 'dark' ? 'dark-preview' : 'light-preview'}`} /><strong>{theme === 'dark' ? 'Oscuro' : 'Claro'}</strong><small>{theme === 'dark' ? 'Negative Zone' : 'Kirby Print'}</small></button>
}

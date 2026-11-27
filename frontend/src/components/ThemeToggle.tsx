import { Moon, Sun } from 'lucide-react';
import { useTheme } from '../controllers/useTheme';

export default function ThemeToggle() {
  const { theme, toggleTheme, saving } = useTheme();
  return (
    <button
      className="theme-toggle"
      type="button"
      onClick={toggleTheme}
      disabled={saving}
      aria-label={
        theme === 'dark' ? 'Activar modo claro' : 'Activar modo oscuro'
      }
      title={theme === 'dark' ? 'Modo claro' : 'Modo oscuro'}>
      {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
      <span>{theme === 'dark' ? 'Modo claro' : 'Modo oscuro'}</span>
    </button>
  );
}

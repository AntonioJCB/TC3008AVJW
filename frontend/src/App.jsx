import { useState } from 'react';

const DEMO_USER = 'equipo@baxtersec.com';
const DEMO_PASSWORD = 'KirbyPrint2026!';

function Brand({ className = '' }) {
  return (
    <div className={`brand ${className}`}>
      <span className="brand-mark" aria-hidden="true">B</span>
      <span>BaxterSec</span>
    </div>
  );
}

function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);

  function handleSubmit(event) {
    event.preventDefault();

    // Prototipo visual: sustituir por autenticación del backend antes de producción.
    if (email.trim().toLowerCase() !== DEMO_USER || password !== DEMO_PASSWORD) return;
    onLogin(email.trim(), remember);
  }

  return (
    <section className="login-card" aria-labelledby="login-title">
      <aside className="story-panel">
        <div>
          <div className="eyebrow">Inteligencia de exposición</div>
          <h1>Conoce tu perímetro.<br />Anticípate.</h1>
          <p>Accede al análisis de exposición y monitoreo de activos de tu organización.</p>
          <div className="accent-line" />
        </div>
        <div className="story-caption"><strong>Kirby Print</strong> · Seguridad clara, sin ruido.</div>
      </aside>

      <section className="form-panel">
        <form className="login-form" onSubmit={handleSubmit} noValidate>
          <div className="eyebrow">Acceso de equipo</div>
          <h2 id="login-title">Bienvenido</h2>
          <p className="form-intro">Usa las credenciales que te compartió el equipo.</p>

          <label className="field" htmlFor="email">
            <span>Correo electrónico</span>
            <input
              autoComplete="username"
              id="email"
              name="email"
              onChange={(event) => setEmail(event.target.value)}
              placeholder="nombre@empresa.com"
              type="email"
              value={email}
            />
          </label>

          <label className="field" htmlFor="password">
            <span>Contraseña</span>
            <input
              autoComplete="current-password"
              id="password"
              name="password"
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••••••"
              type="password"
              value={password}
            />
          </label>

          <div className="form-options">
            <label className="remember-option">
              <input checked={remember} onChange={(event) => setRemember(event.target.checked)} type="checkbox" />
              <span>Recordarme</span>
            </label>
            <a href="mailto:admin@baxtersec.com?subject=Solicitar%20acceso">Solicitar ayuda</a>
          </div>

          <button className="submit-button" type="submit">
            Iniciar sesión <span aria-hidden="true">→</span>
          </button>
          <p className="form-footnote">Portal privado · Las cuentas son asignadas por el administrador.</p>
        </form>
      </section>
    </section>
  );
}

function Home({ email, onLogout }) {
  return (
    <section className="home-card" aria-labelledby="home-title">
      <header className="home-header">
        <Brand />
        <button className="logout-button" onClick={onLogout} type="button">Cerrar sesión</button>
      </header>
      <div className="home-content">
        <div className="eyebrow">Espacio de trabajo</div>
        <h1 id="home-title">Home</h1>
        <p>Sesión iniciada como {email}.</p>
        <div className="empty-space">Este espacio está listo para agregar contenido.</div>
      </div>
    </section>
  );
}

export default function App() {
  const [session, setSession] = useState(null);

  function handleLogin(email, remember) {
    setSession({ email, remember });
    document.title = 'BaxterSec · Home';
  }

  function handleLogout() {
    setSession(null);
    document.title = 'BaxterSec · Acceso';
  }

  return (
    <main className="app-shell">
      <header className="site-header">
        <Brand />
        <div className="secure-label"><span aria-hidden="true" />Entorno protegido</div>
      </header>
      <div className="page-content">
        {session
          ? <Home email={session.email} onLogout={handleLogout} />
          : <Login onLogin={handleLogin} />}
      </div>
      <footer className="site-footer">
        <span>Acceso exclusivo para usuarios autorizados.</span>
        <span>© BaxterSec · Portal privado</span>
      </footer>
    </main>
  );
}

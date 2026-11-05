import { useLoginEntry } from '../controller/useLoginEntry'

export default function LoginForm() {
  const { enterPortal, error, submitting } = useLoginEntry()

  return (
    <section className="form-panel">
      <form className="login-form" onSubmit={enterPortal}>
        <div className="eyebrow">Acceso de equipo</div>
        <h2 id="login-title">Bienvenido</h2>

        <label className="field" htmlFor="email">
          <span>Correo electrónico</span>
          <input autoComplete="email" id="email" name="email" placeholder="nombre@empresa.com" type="email" required />
        </label>
        <label className="field" htmlFor="password">
          <span>Contraseña</span>
          <input autoComplete="current-password" id="password" name="password" placeholder="••••••••••••" type="password" required />
        </label>

        {error && <p className="login-error" role="alert">{error}</p>}
        <button className="submit-button" type="submit" disabled={submitting}>
          {submitting ? 'Ingresando…' : 'Entrar al dashboard'} <span aria-hidden="true">→</span>
        </button>
      </form>
    </section>
  )
}

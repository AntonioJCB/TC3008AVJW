import { useDemoEntry } from '../controller/useDemoEntry'

export default function LoginForm() {
  const enterDemo = useDemoEntry()

  return (
    <section className="form-panel">
      <form className="login-form" onSubmit={enterDemo} noValidate>
        <div className="eyebrow">Acceso de equipo</div>
        <h2 id="login-title">Bienvenido</h2>
        <p className="form-intro">Explora BaxterSec con un escenario ficticio. Puedes continuar sin llenar los campos.</p>

        <label className="field" htmlFor="email">
          <span>Correo electrónico <small>(opcional)</small></span>
          <input autoComplete="off" id="email" name="email" placeholder="nombre@empresa.com" type="email" />
        </label>
        <label className="field" htmlFor="password">
          <span>Contraseña <small>(opcional)</small></span>
          <input autoComplete="off" id="password" name="password" placeholder="••••••••••••" type="password" />
        </label>

        <div className="form-options demo-access-row"><span>Sin cuenta ni validación</span><span>DEMO</span></div>
        <button className="submit-button" type="submit">Entrar al dashboard <span aria-hidden="true">→</span></button>
        <p className="form-footnote">Los campos son solo visuales. No se envían ni guardan datos.</p>
      </form>
    </section>
  )
}

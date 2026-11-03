import { useEffect } from 'react'
import Brand from '../../components/Brand'
import LoginForm from './components/LoginForm'
import LoginStory from './components/LoginStory'
import './login.css'

export default function LoginPage() {
  useEffect(() => { document.title = 'BaxterSec · Acceso' }, [])

  return (
    <div className="site-shell login-shell">
      <header className="site-header">
        <Brand />
      </header>
      <main className="page-content">
        <section className="login-card" aria-labelledby="login-title">
          <LoginStory />
          <LoginForm />
        </section>
      </main>
      <footer className="site-footer">
        <span>© BaxterSec</span>
      </footer>
    </div>
  )
}

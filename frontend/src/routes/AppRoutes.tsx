import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router'
import LoginPage from '../pages/login/LoginPage'
import PasswordRecoveryPage from '../pages/login/PasswordRecoveryPage'
import DashboardPage from '../pages/dashboard/ClientPortalPage'
import AdminPage from '../pages/admin/AdminPortalPage'
import AdminClientPage from '../pages/admin/AdminClientPage'
import ThemeProvider from '../controllers/ThemeProvider'
import AuthProvider from '../controllers/AuthProvider'
import RequireAuth from './RequireAuth'

export default function AppRoutes() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <ScrollToTop />
          <Routes>
            <Route path="/" element={<Navigate to="/login" replace />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/restablecer-clave" element={<PasswordRecoveryPage />} />
            <Route path="/home" element={<RequireAuth><DashboardPage /></RequireAuth>} />
            <Route path="/home/:section" element={<RequireAuth><DashboardPage /></RequireAuth>} />
            <Route path="/admin" element={<RequireAuth platformOnly><AdminPage /></RequireAuth>} />
            <Route path="/admin/clientes/:id" element={<RequireAuth platformOnly><AdminClientPage /></RequireAuth>} />
            <Route path="*" element={<Navigate to="/login" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}

function ScrollToTop() {
  const { pathname } = useLocation()
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])
  return null
}

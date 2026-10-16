import type { FormEvent } from 'react'
import { useNavigate } from 'react-router'

/** Navegación local: el prototipo no valida ni transmite credenciales. */
export function useDemoEntry() {
  const navigate = useNavigate()

  return (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    navigate('/home')
  }
}

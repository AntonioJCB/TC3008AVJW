import type { FormEvent } from 'react'
import { useNavigate } from 'react-router'

export function useLoginEntry() {
  const navigate = useNavigate()

  return (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!event.currentTarget.reportValidity()) return
    navigate('/home')
  }
}

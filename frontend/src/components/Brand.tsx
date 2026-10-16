import { Link } from 'react-router'

export default function Brand() {
  return (
    <Link className="brand" to="/login" aria-label="BaxterSec, volver al acceso">
      <span className="brand-mark" aria-hidden="true">B</span>
      <span>BaxterSec</span>
    </Link>
  )
}

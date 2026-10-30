"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { getSupabase } from "@/lib/supabase";

export function Cabecera({ correo }: { correo?: string | null }) {
  const router = useRouter();
  async function salir() {
    await getSupabase().auth.signOut();
    router.replace("/login");
  }
  return (
    <header className="cabecera">
      <Link href="/" className="marca">
        BaxterSec
      </Link>
      <nav>
        <Link href="/escaneos/nuevo">Nuevo escaneo</Link>
        {correo && (
          <>
            <span className="suave">{correo}</span>
            <button type="button" className="boton-secundario" onClick={salir}>
              Salir
            </button>
          </>
        )}
      </nav>
    </header>
  );
}

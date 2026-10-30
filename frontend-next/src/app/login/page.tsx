"use client";

import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { getSupabase } from "@/lib/supabase";
import { textoDeError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [modo, setModo] = useState<"entrar" | "registrar">("entrar");
  const [correo, setCorreo] = useState("");
  const [contrasena, setContrasena] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [aviso, setAviso] = useState<string | null>(null);
  const [cargando, setCargando] = useState(false);

  async function enviar(e: FormEvent) {
    e.preventDefault();
    setCargando(true);
    setError(null);
    setAviso(null);
    try {
      const auth = getSupabase().auth;
      if (modo === "entrar") {
        const { error } = await auth.signInWithPassword({ email: correo, password: contrasena });
        if (error) throw error;
        router.replace("/");
      } else {
        const { data, error } = await auth.signUp({ email: correo, password: contrasena });
        if (error) throw error;
        if (data.session) router.replace("/");
        else setAviso("Cuenta creada. Revisa tu correo para confirmarla y luego inicia sesión.");
      }
    } catch (err) {
      setError(textoDeError(err));
    } finally {
      setCargando(false);
    }
  }

  return (
    <main className="centrado">
      <form className="tarjeta formulario" onSubmit={enviar}>
        <h1>BaxterSec</h1>
        <p className="suave">{modo === "entrar" ? "Inicia sesión" : "Crea tu cuenta"}</p>
        <label>
          Correo
          <input type="email" required value={correo} onChange={(e) => setCorreo(e.target.value)} autoComplete="email" />
        </label>
        <label>
          Contraseña
          <input
            type="password"
            required
            minLength={8}
            value={contrasena}
            onChange={(e) => setContrasena(e.target.value)}
            autoComplete={modo === "entrar" ? "current-password" : "new-password"}
          />
        </label>
        {error && <p className="error" role="alert">{error}</p>}
        {aviso && <p className="aviso" role="status">{aviso}</p>}
        <button type="submit" disabled={cargando}>
          {cargando ? "Un momento…" : modo === "entrar" ? "Entrar" : "Crear cuenta"}
        </button>
        <button type="button" className="boton-secundario" onClick={() => setModo(modo === "entrar" ? "registrar" : "entrar")}>
          {modo === "entrar" ? "No tengo cuenta" : "Ya tengo cuenta"}
        </button>
      </form>
    </main>
  );
}

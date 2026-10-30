"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { getSupabase } from "@/lib/supabase";

/** Exige una sesión de Supabase: si no hay, envía a /login. */
export function useSesion() {
  const router = useRouter();
  const [correo, setCorreo] = useState<string | null>(null);
  const [listo, setListo] = useState(false);

  useEffect(() => {
    const supabase = getSupabase();
    let activo = true;

    supabase.auth.getSession().then(({ data }) => {
      if (!activo) return;
      if (!data.session) router.replace("/login");
      else {
        setCorreo(data.session.user.email ?? null);
        setListo(true);
      }
    });
    const { data: suscripcion } = supabase.auth.onAuthStateChange((_evento, sesion) => {
      if (!sesion) router.replace("/login");
    });
    return () => {
      activo = false;
      suscripcion.subscription.unsubscribe();
    };
  }, [router]);

  return { listo, correo };
}

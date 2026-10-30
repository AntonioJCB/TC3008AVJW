import { createClient, type SupabaseClient } from "@supabase/supabase-js";

let cliente: SupabaseClient | null = null;

/**
 * Cliente de Supabase para el navegador. Solo se usa para la sesión (login) y
 * para leer las autorizaciones de dominio, que Row Level Security limita a tu
 * organización. Todo lo demás pasa por la API FastAPI.
 */
export function getSupabase(): SupabaseClient {
  if (cliente) return cliente;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) {
    throw new Error("Falta NEXT_PUBLIC_SUPABASE_URL o NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY en .env.local");
  }
  cliente = createClient(url, key);
  return cliente;
}

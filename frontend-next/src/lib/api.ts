import { getSupabase } from "./supabase";
import type { Escaneo, EscaneoCreado, EscaneoResumen, Hallazgo, Riesgo } from "./tipos";

const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** FastAPI devuelve `detail` como texto, como {codigo, mensaje} o (en 422) como lista de errores. */
function mensajeDeError(status: number, cuerpo: unknown): string {
  const detail = (cuerpo as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => (d as { msg?: string }).msg ?? "Dato inválido").join("; ");
  const mensaje = (detail as { mensaje?: string } | undefined)?.mensaje;
  return mensaje ?? `Error ${status} del servidor`;
}

async function pedir<T>(ruta: string, init: RequestInit = {}): Promise<T> {
  const { data } = await getSupabase().auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new ApiError(401, "Inicia sesión para continuar");

  let respuesta: Response;
  try {
    respuesta = await fetch(`${API_URL}${ruta}`, {
      ...init,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...init.headers },
    });
  } catch {
    throw new ApiError(0, `No se pudo conectar con la API (${API_URL}). ¿Está corriendo el backend?`);
  }
  if (!respuesta.ok) {
    const cuerpo: unknown = await respuesta.json().catch(() => null);
    throw new ApiError(respuesta.status, mensajeDeError(respuesta.status, cuerpo));
  }
  return (await respuesta.json()) as T;
}

export const api = {
  /** Crea el escaneo (el dominio es siempre el de tu organización, nunca se envía). */
  crearEscaneo: (autorizacionId: string) =>
    pedir<EscaneoCreado>("/api/escaneos", { method: "POST", body: JSON.stringify({ autorizacion_id: autorizacionId }) }),

  /** Responde de inmediato (202); las fuentes corren en segundo plano. */
  ejecutarEscaneo: (id: string) => pedir<Escaneo>(`/api/escaneos/${id}/ejecutar`, { method: "POST" }),

  obtenerEscaneo: (id: string) => pedir<Escaneo>(`/api/escaneos/${id}`),
  listarEscaneos: (limite = 20) => pedir<EscaneoResumen[]>(`/api/escaneos?limit=${limite}`),
  obtenerHallazgos: (id: string) => pedir<Hallazgo[]>(`/api/escaneos/${id}/hallazgos`),
  recalcularRiesgo: (id: string) => pedir<Riesgo>(`/api/escaneos/${id}/riesgo/recalcular`, { method: "POST" }),
};

export function textoDeError(error: unknown): string {
  return error instanceof Error ? error.message : "Ocurrió un error inesperado";
}

import type { MotivoNoEvaluada, Severidad } from "./tipos";

export const ETIQUETA_CATEGORIA: Record<string, string> = {
  infraestructura: "Infraestructura",
  identidad_digital: "Identidad digital",
  configuracion: "Configuración",
  fuga_de_datos: "Fuga de datos",
};

export const ETIQUETA_SEVERIDAD: Record<Severidad, string> = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
};

export const ETIQUETA_MOTIVO: Record<MotivoNoEvaluada["motivo"], string> = {
  inactiva: "desactivada en el catálogo",
  sin_evaluador: "requiere fuentes que aún no están integradas",
  fuentes_fallidas: "las fuentes que la alimentan fallaron en este escaneo",
  categoria_invalida: "categoría inválida en el catálogo",
};

export function fecha(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString("es-MX", { dateStyle: "medium", timeStyle: "short" }) : "—";
}

/** 0-100 → nivel de riesgo para colorear. */
export function nivelDeRiesgo(puntaje: number): "bajo" | "medio" | "alto" | "critico" {
  if (puntaje >= 75) return "critico";
  if (puntaje >= 50) return "alto";
  if (puntaje >= 25) return "medio";
  return "bajo";
}

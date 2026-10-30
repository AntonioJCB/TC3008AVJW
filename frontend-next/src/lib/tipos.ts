// Tipos que reflejan las respuestas de la API FastAPI (backend/app/main.py).

export type EstadoEscaneo = "pendiente" | "ejecutando" | "completado" | "incompleto" | "fallido";
export type EstadoFuente = "pendiente" | "ejecutando" | "completado" | "fallido";
export type Severidad = "critica" | "alta" | "media" | "baja";

export const ESTADOS_FINALES: readonly EstadoEscaneo[] = ["completado", "incompleto", "fallido"];
export const FUENTES = ["crt.sh", "Shodan", "theHarvester", "SpiderFoot"] as const;

export interface Fuente {
  fuente: string;
  estado: EstadoFuente;
  error: string | null;
  resultado_crudo_id: string | null;
  iniciado_en: string | null;
  finalizado_en: string | null;
  /** true si este mismo resultado ya se había procesado antes (no se duplicó nada). */
  ya_procesado: boolean;
  observaciones_generadas: number;
  activos_nuevos: number;
  activos_existentes: number;
  observaciones_nuevas: number;
  observaciones_duplicadas: number;
  /** Datos que no se guardaron, por motivo (p. ej. fuera_de_alcance). */
  descartadas: Record<string, number>;
}

export interface MotivoNoEvaluada {
  codigo: string;
  motivo: "inactiva" | "sin_evaluador" | "fuentes_fallidas" | "categoria_invalida";
}

export interface Cobertura {
  total_reglas: number;
  evaluadas: string[];
  no_evaluadas: MotivoNoEvaluada[];
  porcentaje_evaluadas: number;
}

export interface Riesgo {
  puntaje_global: number;
  infraestructura: number;
  identidad_digital: number;
  configuracion: number;
  fuga_de_datos: number;
  /** true si alguna fuente falló: el puntaje no vio todo y puede estar subestimado. */
  es_parcial: boolean;
  fuentes_faltantes: string[];
  cobertura: Cobertura;
  version_motor: string | null;
  calculado_en: string | null;
}

export interface Escaneo {
  escaneo_id: string;
  estado: EstadoEscaneo;
  dominio: string | null;
  /** Frase lista para mostrar: qué fuentes fallaron y cuáles no. */
  mensaje: string;
  fuentes: Fuente[];
  fuentes_ok: string[];
  fuentes_fallidas: string[];
  iniciado_en: string | null;
  finalizado_en: string | null;
  riesgo: Riesgo | null;
}

export interface EscaneoResumen {
  escaneo_id: string;
  estado: EstadoEscaneo;
  dominio: string;
  iniciado_en: string | null;
  finalizado_en: string | null;
  puntaje_global: number | null;
  es_parcial: boolean | null;
}

export interface EscaneoCreado {
  escaneo_id: string;
  estado: EstadoEscaneo;
  dominio: string;
}

export interface Hallazgo {
  id: string;
  regla_codigo: string | null;
  regla_nombre: string | null;
  descripcion: string | null;
  categoria: string;
  severidad: Severidad;
  confianza: number;
  estado: string;
  activo_tipo: string | null;
  activo_valor: string | null;
  fuentes: string[];
  evidencia: Record<string, unknown>;
}

export interface Autorizacion {
  id: string;
  alcance: string;
  expira_en: string | null;
  revocada_en: string | null;
}

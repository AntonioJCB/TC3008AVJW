"""Diagnóstico de lectura: python -m app.check_supabase (desde backend)."""
from __future__ import annotations

import httpx
from supabase import create_client

from app.settings import get_settings


# Comprueba también columnas y relaciones usadas por los endpoints, sin imprimir filas.
CONSULTAS = {
    "usuarios": "id,organizacion_id,rol,esta_activo",
    "organizaciones": "id,dominio_principal",
    "autorizaciones_dominio": "id,organizacion_id,alcance,expira_en,revocada_en",
    "escaneos": "id,organizacion_id,solicitado_por,autorizacion_id,estado,iniciado_en,finalizado_en",
    "fuentes_osint": "id,nombre",
    "resultados_crudos": "id,escaneo_id,fuente_id,hash_contenido,estado",
    "resultados_fuentes": "escaneo_id,estado,error,resultado_crudo_id,observaciones_generadas,descartadas,fuentes_osint(nombre)",
    "activos": "id,tipo,valor",
    "observaciones": "id,activo_id,atributo,datos,observado_en,fuente_id,activos(tipo,valor),fuentes_osint(nombre)",
    "reglas_riesgo": "id,codigo,nombre,categoria,severidad,peso,esta_activa",
    "hallazgos": "id,categoria,severidad,confianza,estado,evidencia,reglas_riesgo(codigo,nombre,descripcion),activos(tipo,valor),fuentes_osint(nombre)",
    "puntajes_riesgo": "escaneo_id,puntaje_global,infraestructura,identidad_digital,configuracion,fuga_de_datos,es_parcial,fuentes_faltantes,cobertura,version_motor,calculado_en",
}


def main() -> int:
    try:
        settings = get_settings()
        client = create_client(settings.supabase_url, settings.supabase_service_role_key)
    except Exception as error:
        # No imprimir excepciones arbitrarias: podrían incluir credenciales.
        message = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        print("ERROR configuración:", message)
        return 1

    failures = 0
    for table, columns in CONSULTAS.items():
        try:
            client.table(table).select(columns).limit(1).execute()
            print(f"OK {table}")
        except httpx.RequestError:
            print(f"ERROR {table}: conexión de red; comprueba URL, DNS y disponibilidad del proyecto")
            return 1
        except Exception as error:
            code = str(getattr(error, "code", type(error).__name__))
            print(f"ERROR {table}: código {code}; revisa credenciales, migraciones y permisos")
            failures += 1

    print("Esta comprobación solo lee; no valida escrituras, RLS de usuarios ni la RPC guardar_riesgo.")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())

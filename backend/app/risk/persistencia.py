"""Lectura de observaciones y escritura de hallazgos/puntajes en Supabase."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any, Callable

from app.osint_normalization import parsear_servicio
from app.risk.modelos import Hallazgo, Obs, Regla, ResultadoRiesgo
from app.risk.motor import aporte_hallazgo, calcular_riesgo_potencial, evaluar_riesgo, puntuar_hallazgos
from app.risk.reglas import DEFINICIONES
from app.scan_scope import scope_allows_domain, scope_allows_ip
from app.source_policy import ACTIVE_SOURCES, RETIRED_RISK_RULES

PAGINA = 1000
ORDEN_SEVERIDAD = {"critica": 0, "alta": 1, "media": 2, "baja": 3}
ETIQUETA_SEVERIDAD = {"critica": "Crítica", "alta": "Alta", "media": "Media", "baja": "Baja"}
ESTADOS_HALLAZGO_VIGENTE = {"abierto", "nuevo", "revisado", "aceptado"}


def _nivel_severidad(value: str) -> str:
    normalized = value.lower().replace("í", "i")
    return {"critical": "critica", "high": "alta", "medium": "media", "low": "baja"}.get(
        normalized, normalized,
    )


def _paginar(construir: Callable[[int, int], Any]) -> list[dict[str, Any]]:
    """PostgREST devuelve como máximo ~1000 filas por petición: se pide por páginas."""
    filas: list[dict[str, Any]] = []
    inicio = 0
    while True:
        pagina = construir(inicio, inicio + PAGINA - 1).execute().data or []
        filas.extend(pagina)
        if len(pagina) < PAGINA:
            return filas
        inicio += PAGINA


def cargar_observaciones(client: Any, scan_id: str) -> list[Obs]:
    filas = _paginar(
        lambda a, b: client.table("observaciones")
        .select("id, activo_id, atributo, datos, observado_en, fuente_id, activos(tipo, valor), fuentes_osint(nombre)")
        .eq("escaneo_id", scan_id)
        .order("id")
        .range(a, b)
    )
    return [
        Obs(
            id=str(f["id"]),
            activo_id=str(f["activo_id"]),
            tipo=f["activos"]["tipo"],
            valor=f["activos"]["valor"],
            atributo=f["atributo"],
            datos=f.get("datos") or {},
            fuente=f["fuentes_osint"]["nombre"],
            fuente_id=str(f["fuente_id"]),
            observado_en=f.get("observado_en"),
        )
        for f in filas
        if f.get("activos") and f.get("fuentes_osint")
        and f["fuentes_osint"]["nombre"] in ACTIVE_SOURCES
    ]


def cargar_reglas(client: Any) -> list[Regla]:
    filas = client.table("reglas_riesgo").select("id, codigo, nombre, categoria, severidad, peso, esta_activa").execute().data or []
    return [
        Regla(str(f["id"]), f["codigo"], f["nombre"], f["categoria"], f["severidad"], int(f["peso"]), bool(f["esta_activa"]))
        for f in filas
    ]


def cargar_estado_fuentes(client: Any, scan_id: str) -> dict[str, str]:
    filas = (
        client.table("resultados_fuentes").select("estado, error, fuentes_osint(nombre)").eq("escaneo_id", scan_id).execute().data
        or []
    )
    return {
        f["fuentes_osint"]["nombre"]: "parcial" if f["estado"] == "completado" and f.get("error") else f["estado"]
        for f in filas if f.get("fuentes_osint")
        and f["fuentes_osint"]["nombre"] in ACTIVE_SOURCES
    }


def _alcance_escaneo(client: Any, scan_id: str) -> str:
    scan = client.table("escaneos").select("autorizacion_id").eq("id", scan_id).single().execute().data
    if not scan or not scan.get("autorizacion_id"):
        raise ValueError("El escaneo no tiene una autorización válida")
    authorization = (
        client.table("autorizaciones_dominio").select("alcance")
        .eq("id", scan["autorizacion_id"]).single().execute().data
    )
    if not authorization:
        raise ValueError("No se encontró el alcance autorizado del escaneo")
    return str(authorization.get("alcance") or "")


def _servicio_autorizado(valor: str, scope: str) -> bool:
    service = parsear_servicio(valor)
    return bool(service and scope_allows_ip(scope, service["ip"]))


def _observaciones_atribuidas(observaciones: list[Obs], scope: str) -> tuple[list[Obs], int]:
    """Excluye del puntaje puertos de IPs compartidas sin autorización IP propia."""
    validas = [
        obs for obs in observaciones
        if obs.atributo not in {"servicio_expuesto", "cve"}
        or (obs.tipo == "servicio" and _servicio_autorizado(obs.valor, scope))
        or (obs.tipo == "ip" and scope_allows_ip(scope, obs.valor))
        or (obs.tipo in {"dominio", "subdominio"} and scope_allows_domain(scope, obs.valor))
        or obs.tipo not in {"servicio", "ip", "dominio", "subdominio"}
    ]
    return validas, len(observaciones) - len(validas)


def _hallazgo_atribuido(row: dict[str, Any], scope: str) -> bool:
    detalle = (row.get("evidencia") or {}).get("detalle") or {}
    codigo = (row.get("evidencia") or {}).get("regla")
    if codigo in {"CONF-006", "CONF-007", "CONF-008"}:
        return scope_allows_domain(scope, str(detalle.get("activo") or ""))
    if codigo not in {"INFRA-001", "INFRA-002", "INFRA-003"}:
        return True
    service = detalle.get("servicio") or detalle.get("activo")
    if service:
        return (_servicio_autorizado(str(service), scope)
                or scope_allows_ip(scope, str(service))
                or scope_allows_domain(scope, str(service)))
    return scope_allows_ip(scope, str(detalle.get("ip") or ""))


def _hallazgos_previos(client: Any, scan_id: str) -> tuple[str | None, list[dict[str, Any]]]:
    """Busca el último snapshot de riesgo persistente de la misma organización.

    Los puntajes antiguos no tienen la marca de persistencia: esto evita arrastrar
    los hallazgos de demostración que se mezclaron con los primeros escaneos reales.
    """
    scan = (
        client.table("escaneos").select("organizacion_id, finalizado_en")
        .eq("id", scan_id).single().execute().data
    )
    if not scan or not scan.get("finalizado_en"):
        raise ValueError("El escaneo debe haber terminado antes de calcular el riesgo")

    inicio = 0
    while True:
        anteriores = (
            client.table("escaneos").select("id")
            .eq("organizacion_id", scan["organizacion_id"])
            .lt("finalizado_en", scan["finalizado_en"])
            .order("finalizado_en", desc=True)
            .range(inicio, inicio + 99).execute().data or []
        )
        if not anteriores:
            return None, []
        ids = [row["id"] for row in anteriores]
        riesgos = (
            client.table("puntajes_riesgo").select("escaneo_id, cobertura")
            .in_("escaneo_id", ids).execute().data or []
        )
        elegibles = {
            row["escaneo_id"] for row in riesgos
            if (row.get("cobertura") or {}).get("persistencia_hallazgos") is True
        }
        anterior_id = next((row["id"] for row in anteriores if row["id"] in elegibles), None)
        if anterior_id:
            filas = _paginar(
                lambda a, b: client.table("hallazgos")
                .select("activo_id, regla_id, fuente_id, categoria, severidad, confianza, evidencia, estado")
                .eq("escaneo_id", anterior_id)
                .in_("estado", ["abierto", "nuevo", "revisado", "aceptado"])
                .order("id").range(a, b)
            )
            return anterior_id, filas
        if len(anteriores) < 100:
            return None, []
        inicio += 100


def _resueltos_en_escaneo(client: Any, scan_id: str) -> set[tuple[str, str]]:
    filas = _paginar(
        lambda a, b: client.table("hallazgos")
        .select("activo_id, regla_id").eq("escaneo_id", scan_id)
        .in_("estado", ["resuelto", "falso_positivo", "descartado"])
        .order("id").range(a, b)
    )
    return {(row["activo_id"], row["regla_id"]) for row in filas if row.get("regla_id")}


def _consolidar_hallazgos(
    actuales: list[Hallazgo], anteriores: list[dict[str, Any]],
    resueltos: set[tuple[str, str]], reglas: list[Regla], scan_id: str, anterior_id: str | None,
) -> tuple[list[Hallazgo], int]:
    """La detección actual reemplaza evidencia previa; lo no resuelto permanece."""
    vigentes: dict[tuple[str, str], Hallazgo] = {}
    estados_previos = {
        (row["activo_id"], row["regla_id"]): row["estado"]
        for row in anteriores
        if row.get("estado") in {"abierto", "nuevo", "revisado", "aceptado"}
        and (row.get("evidencia") or {}).get("retirado_del_riesgo") is not True
    }
    rank = {"sin_clasificar": -1, "potencial": 0, "confirmada": 1}
    for hallazgo in actuales:
        clave = (hallazgo.activo_id, hallazgo.regla_id)
        if clave in resueltos:
            continue
        hallazgo.estado = estados_previos.get(clave, "abierto")
        hallazgo.evidencia["ultimo_escaneo_con_evidencia"] = scan_id
        hallazgo.evidencia["pendiente_revalidacion"] = False
        current = vigentes.get(clave)
        if current is None or rank[hallazgo.nivel_evidencia] > rank[current.nivel_evidencia]:
            vigentes[clave] = hallazgo

    por_id = {regla.id: regla for regla in reglas
              if regla.esta_activa and regla.codigo in DEFINICIONES
              and regla.codigo not in RETIRED_RISK_RULES}
    arrastrados = 0
    for row in anteriores:
        clave = (row["activo_id"], row["regla_id"])
        regla = por_id.get(row["regla_id"])
        if clave in vigentes or clave in resueltos or regla is None or not anterior_id:
            continue
        evidencia = dict(row.get("evidencia") or {})
        if evidencia.get("retirado_del_riesgo") is True:
            continue
        evidencia["ultimo_escaneo_con_evidencia"] = evidencia.get("ultimo_escaneo_con_evidencia") or anterior_id
        evidencia["pendiente_revalidacion"] = True
        nivel = evidencia.get("nivel_evidencia", "sin_clasificar")
        if nivel not in {"potencial", "confirmada", "sin_clasificar"}:
            nivel = "sin_clasificar"
        evidencia["peso"] = regla.peso
        aporte = round(aporte_hallazgo(regla.peso, float(row["confianza"])), 2)
        if nivel == "confirmada":
            evidencia["aporte"] = aporte
            evidencia.pop("aporte_potencial_estimado", None)
        elif nivel == "potencial":
            evidencia["aporte_potencial_estimado"] = aporte
            evidencia.pop("aporte", None)
        else:
            evidencia.pop("aporte", None)
            evidencia.pop("aporte_potencial_estimado", None)
        vigentes[clave] = Hallazgo(
            activo_id=row["activo_id"], regla_id=regla.id, regla_codigo=regla.codigo,
            fuente_id=row["fuente_id"], categoria=regla.categoria, severidad=regla.severidad,
            confianza=float(row["confianza"]), evidencia=evidencia, estado=row["estado"],
            nivel_evidencia=nivel,
            antiguedad_dias=evidencia.get("antiguedad_dias") if isinstance(evidencia.get("antiguedad_dias"), int) else None,
            motivo_no_confirmado=(evidencia.get("motivo_no_confirmado")
                                  if isinstance(evidencia.get("motivo_no_confirmado"), str) else None),
        )
        arrastrados += 1
    return list(vigentes.values()), arrastrados


def _actualizar_exposicion(
    report: dict[str, Any], hallazgos: list[Hallazgo], reglas: list[Regla],
) -> None:
    """Añade al reporte existente el estado de exposición calculado por activo."""
    reglas_puntuables = {regla.id for regla in reglas if regla.esta_activa and regla.peso > 0}
    por_activo: dict[str, list[Hallazgo]] = {}
    for hallazgo in hallazgos:
        if (hallazgo.nivel_evidencia == "confirmada" and hallazgo.regla_id in reglas_puntuables
                and hallazgo.estado in ESTADOS_HALLAZGO_VIGENTE):
            por_activo.setdefault(hallazgo.activo_id, []).append(hallazgo)
    for asset in report.get("activos") or []:
        vigentes = por_activo.get(str(asset.get("id")), [])
        if vigentes:
            severity = min(
                (_nivel_severidad(str(item.severidad)) for item in vigentes),
                key=lambda value: ORDEN_SEVERIDAD.get(value, 99),
            )
            asset["exposicion"] = ETIQUETA_SEVERIDAD.get(severity, "Baja")
        elif asset.get("evaluado_seguridad") is True:
            asset["exposicion"] = "Evaluado sin hallazgos"
        else:
            asset["exposicion"] = {
                "fuera_alcance": "Fuera de alcance",
                "sin_compatibilidad": "Sin evaluación compatible",
                "historico_sintetico": "Histórico/sintético",
            }.get(asset.get("clasificacion_exposicion"), "Sin evaluar")
        asset["hallazgos_vigentes"] = len(vigentes)
        asset["estado_cobertura"] = (
            "evaluado" if asset.get("evaluado_seguridad") is True
            else "parcial" if asset.get("consultas")
            else asset.get("clasificacion_exposicion", "sin_evaluacion")
        )


def calcular_y_guardar(client: Any, scan_id: str, ahora: datetime | None = None, report: dict | None = None) -> ResultadoRiesgo:
    """Calcula el riesgo de un escaneo y lo guarda de forma atómica (RPC guardar_riesgo)."""
    riesgo_existente = leer_riesgo(client, scan_id)
    historico_anterior = bool(
        riesgo_existente and not (riesgo_existente.get("cobertura") or {}).get("persistencia_hallazgos")
    )
    scope = _alcance_escaneo(client, scan_id)
    observaciones, excluidas = _observaciones_atribuidas(
        [obs for obs in cargar_observaciones(client, scan_id) if obs.fuente in ACTIVE_SOURCES], scope
    )
    # La política impide puntuar Web aunque el catálogo remoto aún no se haya actualizado.
    reglas = [replace(regla, esta_activa=False) if regla.codigo in RETIRED_RISK_RULES else regla
              for regla in cargar_reglas(client)]
    resultado = evaluar_riesgo(
        observaciones, reglas, cargar_estado_fuentes(client, scan_id), ahora
    )
    anterior_id, anteriores = (None, []) if historico_anterior else _hallazgos_previos(client, scan_id)
    anteriores = [row for row in anteriores if _hallazgo_atribuido(row, scope)]
    resultado.hallazgos, arrastrados = _consolidar_hallazgos(
        resultado.hallazgos, anteriores, _resueltos_en_escaneo(client, scan_id),
        reglas, scan_id, anterior_id,
    )
    puntuacion = puntuar_hallazgos(resultado.hallazgos, reglas)
    for campo, valor in puntuacion.items():
        setattr(resultado.puntaje, campo, valor)
    resultado.puntaje.cobertura["riesgo_potencial"] = calcular_riesgo_potencial(
        resultado.hallazgos, reglas,
    )
    resultado.puntaje.es_parcial = resultado.puntaje.es_parcial or arrastrados > 0
    resultado.puntaje.cobertura.update({
        "persistencia_hallazgos": not historico_anterior,
        "hallazgos_arrastrados": arrastrados,
        "hallazgos_pendientes_revalidacion": arrastrados,
        "observaciones_servicio_sin_ip_autorizada": excluidas,
    })
    report = report or (riesgo_existente or {}).get("cobertura", {}).get("infraestructura")
    if report:
        _actualizar_exposicion(report, resultado.hallazgos, reglas)
        resultado.puntaje.cobertura["infraestructura"] = report
        resultado.puntaje.es_parcial |= bool(report.get("cobertura_incompleta"))
    client.rpc(
        "guardar_riesgo",
        {
            "p_escaneo_id": scan_id,
            "p_hallazgos": [h.como_dict() for h in resultado.hallazgos],
            "p_puntaje": resultado.puntaje.como_dict(),
        },
    ).execute()
    return resultado


def leer_riesgo(client: Any, scan_id: str) -> dict[str, Any] | None:
    filas = (
        client.table("puntajes_riesgo")
        .select(
            "puntaje_global, infraestructura, identidad_digital, configuracion, fuga_de_datos, "
            "es_parcial, fuentes_faltantes, cobertura, version_motor, calculado_en"
        )
        .eq("escaneo_id", scan_id)
        .limit(1)
        .execute()
        .data
    )
    return filas[0] if filas else None


def leer_hallazgos(client: Any, scan_id: str) -> list[dict[str, Any]]:
    filas = _paginar(
        lambda a, b: client.table("hallazgos")
        .select(
            "id, categoria, severidad, confianza, estado, evidencia, "
            "reglas_riesgo(codigo, nombre, descripcion), activos(tipo, valor), fuentes_osint(nombre)"
        )
        .eq("escaneo_id", scan_id)
        .order("id")
        .range(a, b)
    )
    return sorted(
        [fila for fila in filas if (fila.get("evidencia") or {}).get("retirado_del_riesgo") is not True],
        key=lambda f: (ORDEN_SEVERIDAD.get(f["severidad"], 9), -float(f["confianza"] or 0), (f.get("reglas_riesgo") or {}).get("codigo", "")),
    )

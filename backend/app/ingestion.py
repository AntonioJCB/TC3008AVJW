from __future__ import annotations

from typing import Any

from supabase import Client

from app.osint_normalization import adaptar, hash_contenido


BATCH_SIZE = 1000


def _execute(query: Any) -> Any:
    response = query.execute()
    return response.data


def _count_discarded(discarded: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in discarded:
        reason = item["motivo"]
        counts[reason] = counts.get(reason, 0) + 1
    return counts


def _empty_summary(raw_id: str, already_processed: bool = False) -> dict[str, Any]:
    return {
        "resultado_crudo_id": raw_id,
        "ya_procesado": already_processed,
        "observaciones_generadas": 0,
        "activos_nuevos": 0,
        "activos_existentes": 0,
        "observaciones_nuevas": 0,
        "observaciones_duplicadas": 0,
        "descartadas": {},
    }


def _save_raw_result(
    client: Client,
    scan_id: str,
    source_id: str,
    raw: Any,
    content_hash: str,
) -> tuple[str, str]:
    inserted = _execute(
        client.table("resultados_crudos")
        .upsert(
            {
                "escaneo_id": scan_id,
                "fuente_id": source_id,
                "estado": "pendiente",
                "contenido": raw,
                "hash_contenido": content_hash,
            },
            on_conflict="escaneo_id,fuente_id,hash_contenido",
            ignore_duplicates=True,
        )
    ) or []
    if inserted:
        return str(inserted[0]["id"]), str(inserted[0].get("estado") or "pendiente")

    existing = _execute(
        client.table("resultados_crudos")
        .select("id, estado")
        .eq("escaneo_id", scan_id)
        .eq("fuente_id", source_id)
        .eq("hash_contenido", content_hash)
        .single()
    )
    if not existing:
        raise RuntimeError("No se pudo recuperar el resultado crudo existente")
    return str(existing["id"]), str(existing.get("estado") or "pendiente")


def _call_ingestion_rpc(
    client: Client,
    organization_id: str,
    scan_id: str,
    source_id: str,
    raw_id: str,
    items: list[dict[str, Any]],
    mark_processed: bool,
) -> dict[str, int]:
    data = _execute(
        client.rpc(
            "ingestar_observaciones",
            {
                "p_organizacion_id": organization_id,
                "p_escaneo_id": scan_id,
                "p_fuente_id": source_id,
                "p_resultado_crudo_id": raw_id,
                "p_items": items,
                "p_marcar_procesado": mark_processed,
            },
        )
    )
    row = data[0] if isinstance(data, list) and data else data
    if not isinstance(row, dict):
        raise RuntimeError("La función de ingesta no devolvió los contadores esperados")
    return {
        "activos_nuevos": int(row.get("activos_nuevos") or 0),
        "activos_existentes": int(row.get("activos_existentes") or 0),
        "observaciones_nuevas": int(row.get("observaciones_nuevas") or 0),
        "observaciones_duplicadas": int(row.get("observaciones_duplicadas") or 0),
    }


def ingestar_resultado(
    client: Client,
    *,
    organization_id: str,
    scan_id: str,
    source_id: str,
    source: str,
    raw: Any,
    domain: str,
    ips_in_scope: list[str] | None = None,
) -> dict[str, Any]:
    content_hash = hash_contenido(raw)
    raw_id, raw_status = _save_raw_result(client, scan_id, source_id, raw, content_hash)
    if raw_status == "procesado":
        return _empty_summary(raw_id, already_processed=True)

    try:
        adapted = adaptar(source, raw, domain, ips_in_scope)
        observations = adapted["observaciones"]
        chunks = [
            observations[offset:offset + BATCH_SIZE]
            for offset in range(0, len(observations), BATCH_SIZE)
        ] or [[]]
        totals = {
            "activos_nuevos": 0,
            "activos_existentes": 0,
            "observaciones_nuevas": 0,
            "observaciones_duplicadas": 0,
        }
        for index, chunk in enumerate(chunks):
            counts = _call_ingestion_rpc(
                client,
                organization_id,
                scan_id,
                source_id,
                raw_id,
                chunk,
                mark_processed=index == len(chunks) - 1,
            )
            for key, count in counts.items():
                totals[key] += count

        return {
            "resultado_crudo_id": raw_id,
            "ya_procesado": False,
            "observaciones_generadas": len(observations),
            **totals,
            "descartadas": _count_discarded(adapted["descartadas"]),
        }
    except Exception:
        try:
            _execute(
                client.table("resultados_crudos")
                .update({"estado": "error"})
                .eq("id", raw_id)
            )
        except Exception:
            pass
        raise
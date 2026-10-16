import argparse
import json
import os
from urllib.parse import unquote, urlparse

import pg8000.dbapi
from dotenv import load_dotenv

from backend.collectors.spiderfoot_file import SpiderFootFileCollector

load_dotenv()

# Valores de texto libre en el esquema: confirmar con el equipo del dashboard.
ESTADO_EN_PROGRESO = "en_progreso"
ESTADO_COMPLETADO = "completado"
ESTADO_FALLIDO = "fallido"
ESTADO_RESULTADO = "ok"

TIPO_ACTIVO = {
    "INTERNET_NAME": "SUBDOMAIN",
    "DOMAIN_NAME": "DOMAIN",
    "EMAIL_ADDRESS": "EMAIL",
    "IP_ADDRESS": "IP",
}


def connect():
    url = urlparse(os.environ["DATABASE_URL"])
    use_ssl = os.environ.get("DB_SSL", "true").lower() != "false"
    return pg8000.dbapi.connect(
        user=unquote(url.username),
        password=unquote(url.password),
        host=url.hostname,
        port=url.port or 5432,
        database=url.path.lstrip("/"),
        ssl_context=True if use_ssl else None,
    )


def query_one(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row


def execute(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    cur.close()


def get_or_create_org(conn, nombre, dominio):
    row = query_one(
        conn, "SELECT id FROM organizaciones WHERE dominio_principal = %s", (dominio,)
    )
    if row:
        return row[0]
    return query_one(
        conn,
        "INSERT INTO organizaciones (nombre, dominio_principal) VALUES (%s, %s) RETURNING id",
        (nombre, dominio),
    )[0]


def get_user_id(conn):
    correo = os.environ["ORQ_USER_EMAIL"]
    row = query_one(conn, "SELECT id FROM usuarios WHERE correo = %s", (correo,))
    if not row:
        raise RuntimeError(f"No existe un usuario con correo {correo} en 'usuarios'")
    return row[0]


def get_or_create_authorization(conn, org_id, user_id):
    row = query_one(
        conn,
        "SELECT id FROM autorizaciones_dominio "
        "WHERE organizacion_id = %s AND revocada_en IS NULL "
        "AND (expira_en IS NULL OR expira_en > now()) "
        "ORDER BY autorizado_en DESC LIMIT 1",
        (org_id,),
    )
    if row:
        return row[0]
    # Atajo de PoC: en producción debe reflejar una autorización real firmada.
    print("Aviso: no había autorización vigente; se registró una de PoC académico")
    return query_one(
        conn,
        "INSERT INTO autorizaciones_dominio "
        "(organizacion_id, autorizado_por, alcance, referencia_documento) "
        "VALUES (%s, %s, %s, %s) RETURNING id",
        (org_id, user_id, "OSINT pasivo", "PoC académico"),
    )[0]


def get_or_create_source(conn, nombre, tipo_acceso="pasivo"):
    row = query_one(conn, "SELECT id FROM fuentes_osint WHERE nombre = %s", (nombre,))
    if row:
        return row[0]
    return query_one(
        conn,
        "INSERT INTO fuentes_osint (nombre, tipo_acceso) VALUES (%s, %s) RETURNING id",
        (nombre, tipo_acceso),
    )[0]


def guardar_activos(conn, org_id, events):
    """Normalización mínima: eventos crudos -> activos sin duplicados."""
    vistos = set()
    nuevos = 0
    for ev in events:
        tipo = TIPO_ACTIVO.get(ev.get("event_type"))
        valor = str(ev.get("data") or "").strip().lower()
        if not tipo or not valor or (tipo, valor) in vistos:
            continue
        vistos.add((tipo, valor))
        row = query_one(
            conn,
            "SELECT id FROM activos WHERE organizacion_id = %s AND tipo = %s AND valor = %s",
            (org_id, tipo, valor),
        )
        if row:
            execute(
                conn, "UPDATE activos SET visto_ultima_vez = now() WHERE id = %s", (row[0],)
            )
        else:
            execute(
                conn,
                "INSERT INTO activos (organizacion_id, tipo, valor) VALUES (%s, %s, %s)",
                (org_id, tipo, valor),
            )
            nuevos += 1
    return len(vistos), nuevos


def run_scan(conn, collector, org_id, user_id, auth_id, fuente_id, domain):
    escaneo_id = query_one(
        conn,
        "INSERT INTO escaneos (organizacion_id, solicitado_por, autorizacion_id, estado, iniciado_en) "
        "VALUES (%s, %s, %s, %s, now()) RETURNING id",
        (org_id, user_id, auth_id, ESTADO_EN_PROGRESO),
    )[0]
    conn.commit()  # el escaneo queda registrado aunque falle la recolección

    try:
        events = collector.collect(domain)
        cur = conn.cursor()
        cur.executemany(
            "INSERT INTO resultados_crudos (escaneo_id, fuente_id, estado, contenido) "
            "VALUES (%s, %s, %s, %s::jsonb)",
            [(escaneo_id, fuente_id, ESTADO_RESULTADO, json.dumps(ev)) for ev in events],
        )
        cur.close()
        total, nuevos = guardar_activos(conn, org_id, events)
        execute(
            conn,
            "UPDATE escaneos SET estado = %s, finalizado_en = now() WHERE id = %s",
            (ESTADO_COMPLETADO, escaneo_id),
        )
        conn.commit()
        print(
            f"Escaneo {escaneo_id} completado: {len(events)} eventos crudos, "
            f"{total} activos únicos ({nuevos} nuevos)"
        )
    except Exception:
        conn.rollback()
        execute(
            conn,
            "UPDATE escaneos SET estado = %s, finalizado_en = now() WHERE id = %s",
            (ESTADO_FALLIDO, escaneo_id),
        )
        conn.commit()
        raise
    return escaneo_id


def main():
    parser = argparse.ArgumentParser(description="Orquestador OSINT")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--name", default=None, help="Nombre de la organización")
    parser.add_argument("--file", required=True, help="JSON exportado de SpiderFoot")
    args = parser.parse_args()

    collector = SpiderFootFileCollector(args.file)

    conn = connect()
    try:
        org_id = get_or_create_org(conn, args.name or args.domain, args.domain)
        user_id = get_user_id(conn)
        auth_id = get_or_create_authorization(conn, org_id, user_id)
        fuente_id = get_or_create_source(conn, collector.name)
        conn.commit()
        run_scan(conn, collector, org_id, user_id, auth_id, fuente_id, args.domain)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
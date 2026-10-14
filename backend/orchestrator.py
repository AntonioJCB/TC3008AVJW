import argparse
import json
import os
from urllib.parse import unquote, urlparse

import pg8000.dbapi
from dotenv import load_dotenv

from backend.collectors.spiderfoot_file import SpiderFootFileCollector

load_dotenv()


def connect():
    url = urlparse(os.environ["DATABASE_URL"])
    return pg8000.dbapi.connect(
        user=unquote(url.username),
        password=unquote(url.password),
        host=url.hostname,
        port=url.port or 5432,
        database=url.path.lstrip("/"),
    )


def query_one(conn, sql: str, params: tuple = ()):
    cur = conn.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    cur.close()
    return row


def execute(conn, sql: str, params: tuple = ()):
    cur = conn.cursor()
    cur.execute(sql, params)
    cur.close()


def get_or_create_org(conn, name: str, domain: str, is_fictional: bool) -> int:
    row = query_one(conn, "SELECT id FROM organizations WHERE domain = %s", (domain,))
    if row:
        return row[0]
    row = query_one(
        conn,
        "INSERT INTO organizations (name, domain, is_fictional) "
        "VALUES (%s, %s, %s) RETURNING id",
        (name, domain, is_fictional),
    )
    return row[0]


def run_scan(conn, collector, org_id: int, domain: str) -> int:
    scan_id = query_one(
        conn,
        "INSERT INTO scans (organization_id, source) VALUES (%s, %s) RETURNING id",
        (org_id, collector.name),
    )[0]
    conn.commit()  # el scan queda registrado aunque falle la recolección

    try:
        events = collector.collect(domain)
        cur = conn.cursor()
        cur.executemany(
            "INSERT INTO raw_results (scan_id, source, payload) "
            "VALUES (%s, %s, %s::jsonb)",
            [(scan_id, collector.name, json.dumps(ev)) for ev in events],
        )
        cur.close()
        execute(
            conn,
            "UPDATE scans SET status = 'done', finished_at = now() WHERE id = %s",
            (scan_id,),
        )
        conn.commit()
        print(f"Scan {scan_id} terminado: {len(events)} eventos guardados")
    except Exception:
        conn.rollback()
        execute(
            conn,
            "UPDATE scans SET status = 'failed', finished_at = now() WHERE id = %s",
            (scan_id,),
        )
        conn.commit()
        raise
    return scan_id


def main():
    parser = argparse.ArgumentParser(description="Orquestador OSINT")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--name", default=None, help="Nombre de la organización")
    parser.add_argument("--file", required=True, help="JSON de SpiderFoot")
    parser.add_argument("--fictional", action="store_true")
    args = parser.parse_args()

    collector = SpiderFootFileCollector(args.file)

    conn = connect()
    try:
        org_id = get_or_create_org(
            conn, args.name or args.domain, args.domain, args.fictional
        )
        conn.commit()
        run_scan(conn, collector, org_id, args.domain)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
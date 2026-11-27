"""BaxterSec: consulta pasiva y acotada de índices públicos Common Crawl."""
import hashlib
import json
import os
import tempfile
import threading
import time

import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from baxter_passive import collect, report_chunks, serialize_report_chunk


def _combined_ca_bundle(custom_ca):
    if not custom_ca:
        return True
    if not os.path.isfile(custom_ca):
        raise FileNotFoundError("El bundle CA configurado no existe")
    with open(requests.certs.where(), "rb") as public_file, open(custom_ca, "rb") as custom_file:
        combined = public_file.read().rstrip() + b"\n" + custom_file.read().lstrip()
    digest = hashlib.sha256(combined).hexdigest()[:16]
    destination = os.path.join(tempfile.gettempdir(), f"baxtersec-ca-{digest}.pem")
    if not os.path.isfile(destination):
        descriptor, temporary = tempfile.mkstemp(prefix="baxtersec-ca-", suffix=".pem")
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(combined)
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return destination


class sfp_baxter_commoncrawl(SpiderFootPlugin):
    meta = {
        "name": "BaxterSec Common Crawl (pasivo)",
        "summary": "Consulta índices históricos públicos sin descargar WARC ni contactar al objetivo.",
        "flags": [], "useCases": ["Passive"], "categories": ["Search Engines"],
    }
    opts = {
        "indexes": os.getenv("SPIDERFOOT_COMMONCRAWL_INDEXES", "2").strip(),
        "max_results": os.getenv("SPIDERFOOT_COMMONCRAWL_MAX_RESULTS", "50").strip(),
        "timeout": os.getenv("SPIDERFOOT_COMMONCRAWL_TIMEOUT", "20").strip(),
        "deadline": os.getenv("SPIDERFOOT_COMMONCRAWL_DEADLINE", "35").strip(),
        "retry_delay": os.getenv("SPIDERFOOT_COMMONCRAWL_RETRY_DELAY", "0.5").strip(),
        "ca_bundle": os.getenv("SPIDERFOOT_CA_BUNDLE", "").strip(),
    }
    optdescs = {
        "indexes": "Cantidad de índices recientes (1 a 3)",
        "max_results": "Máximo de capturas por índice (1 a 100)",
        "timeout": "Tiempo máximo de lectura por intento (5 a 30 segundos)",
        "deadline": "Plazo global del módulo por hostname (15 a 60 segundos)",
        "retry_delay": "Espera entre intentos transitorios (0.1 a 2 segundos)",
        "ca_bundle": "Ruta PEM opcional de una CA institucional añadida al almacén público",
    }

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.opts = {**type(self).opts, **(userOpts or {})}
        self.done = False

    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    def handleEvent(self, event):
        target = self.getTarget().targetValue
        if self.done or event.data != target:
            return
        self.done = True
        last_request = [0.0]
        request_lock = threading.Lock()
        request_timeout = max(5, min(30, int(self.opts.get("timeout") or 20)))
        deadline_seconds = max(15, min(60, float(self.opts.get("deadline") or 35)))
        retry_delay = max(0.1, min(2, float(self.opts.get("retry_delay") or 0.5)))
        deadline_at = time.monotonic() + deadline_seconds
        ca_bundle = _combined_ca_bundle(str(self.opts.get("ca_bundle") or "").strip())

        def fetch(url, params):
            with request_lock:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Se agotó el plazo global de Common Crawl")
                elapsed = time.monotonic() - last_request[0]
                pause = 1.0 - elapsed if last_request[0] and elapsed < 1.0 else 0.0
                if pause:
                    if pause >= remaining:
                        raise TimeoutError("Se agotó el plazo global de Common Crawl")
                    time.sleep(pause)
                last_request[0] = time.monotonic()
            remaining = deadline_at - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Se agotó el plazo global de Common Crawl")
            connect_timeout = min(5.0, max(0.25, remaining / 4))
            read_timeout = min(float(request_timeout), max(0.25, remaining - connect_timeout))
            response = requests.get(
                url, params=params,
                headers={"Accept": "application/json", "User-Agent": "BaxterSec/1.0 academic-passive-osint"},
                timeout=(connect_timeout, read_timeout), allow_redirects=True,
                verify=ca_bundle,
            )
            if url.endswith("collinfo.json"):
                try:
                    payload = response.json()
                except ValueError:
                    payload = None
            elif response.status_code == 404 and "No Captures found for:" in response.text:
                payload = []
            else:
                try:
                    payload = [json.loads(line) for line in response.text.splitlines() if line.strip()]
                except (TypeError, ValueError):
                    payload = None
            return response.status_code, payload

        report = collect(
            "common_crawl", target, fetch,
            commoncrawl_indexes=int(self.opts.get("indexes") or 2),
            commoncrawl_max_results=int(self.opts.get("max_results") or 50),
            commoncrawl_deadline_seconds=deadline_seconds,
            commoncrawl_retry_delay_seconds=retry_delay,
        )
        for chunk in report_chunks(report):
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(chunk), self.__name__, event))

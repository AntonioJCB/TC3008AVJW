"""BaxterSec: consultas a registros existentes, exclusivamente del objetivo."""
import hashlib
import os
import tempfile
import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from baxter_passive import collect, report_chunks, serialize_report_chunk


def _combined_ca_bundle(custom_ca):
    """Trust the public CA store plus an optional institutional CA."""
    if not custom_ca:
        return True
    if not os.path.isfile(custom_ca):
        raise FileNotFoundError("El bundle CA configurado no existe")
    public_ca = requests.certs.where()
    with open(public_ca, "rb") as public_file, open(custom_ca, "rb") as custom_file:
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


class sfp_baxter_urlscan(SpiderFootPlugin):
    meta = {"name": "BaxterSec urlscan (pasivo)", "summary": "Consulta historial del objetivo sin comprobar servicios activos.", "flags": [], "useCases": ["Passive"], "categories": ["Search Engines"]}
    opts = {
        "api_key": os.getenv("SPIDERFOOT_URLSCAN_API_KEY", "").strip(),
        "ca_bundle": os.getenv("SPIDERFOOT_CA_BUNDLE", "").strip(),
        "detail_limit": os.getenv("SPIDERFOOT_URLSCAN_DETAIL_LIMIT", "3").strip(),
        "headers_max_age_days": os.getenv("SPIDERFOOT_URLSCAN_HEADERS_MAX_AGE_DAYS", "90").strip(),
    }
    optdescs = {
        "api_key": "API key opcional de urlscan para cuota e historial de la cuenta",
        "ca_bundle": "Ruta PEM opcional de una CA institucional añadida al almacén público",
        "detail_limit": "Máximo de resultados históricos recientes cuyo detalle HTTP se consulta (0-5)",
        "headers_max_age_days": "Antigüedad máxima (días) para considerar evaluable una respuesta completa",
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
        def fetch(url, params):
            api_key = str(self.opts.get("api_key") or "").strip()
            ca_bundle = str(self.opts.get("ca_bundle") or "").strip()
            headers = {"Accept": "application/json", "User-Agent": "BaxterSec/1.0 academic-passive-osint"}
            if api_key:
                headers["API-Key"] = api_key
            response = requests.get(url, params=params, headers=headers, timeout=30,
                                    allow_redirects=True, verify=_combined_ca_bundle(ca_bundle))
            try:
                payload = response.json()
            except ValueError:
                payload = None
            return response.status_code, payload
        report = collect(
            "urlscan", target, fetch, api_key=str(self.opts.get("api_key") or "").strip(),
            urlscan_detail_limit=int(self.opts.get("detail_limit") or 3),
            urlscan_headers_max_age_days=int(self.opts.get("headers_max_age_days") or 90),
        )
        for chunk in report_chunks(report):
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(chunk), self.__name__, event))

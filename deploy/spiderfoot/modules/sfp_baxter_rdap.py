"""BaxterSec: consulta RDAP pasiva del dominio registrable."""
import hashlib
import os
import tempfile
import threading
import time

import requests
from publicsuffixlist import PublicSuffixList
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from baxter_passive import collect, report_chunks, serialize_report_chunk


_PSL = PublicSuffixList(only_icann=True)
_CACHE = {}
_CACHE_LOCK = threading.Lock()


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


def _registrable_domain(target):
    ascii_target = str(target).strip().lower().rstrip(".").encode("idna").decode("ascii")
    return _PSL.privatesuffix(ascii_target) or ""


class sfp_baxter_rdap(SpiderFootPlugin):
    meta = {
        "name": "BaxterSec RDAP (pasivo)",
        "summary": "Consulta datos públicos del registro del dominio registrable.",
        "flags": [], "useCases": ["Passive"], "categories": ["Search Engines"],
    }
    opts = {"ca_bundle": os.getenv("SPIDERFOOT_CA_BUNDLE", "").strip()}
    optdescs = {"ca_bundle": "Ruta PEM opcional de una CA institucional añadida al almacén público"}

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
        registrable = _registrable_domain(target)

        def fetch(url, params):
            key = (url, tuple(sorted(params.items())))
            now = time.monotonic()
            with _CACHE_LOCK:
                cached = _CACHE.get(key)
                if cached and cached[0] > now:
                    return cached[1], cached[2]
                response = requests.get(
                    url, params=params,
                    headers={"Accept": "application/rdap+json, application/json",
                             "User-Agent": "BaxterSec/1.0 academic-passive-osint"},
                    timeout=30, allow_redirects=True,
                    verify=_combined_ca_bundle(str(self.opts.get("ca_bundle") or "").strip()),
                )
                try:
                    payload = response.json()
                except ValueError:
                    payload = None
                if response.status_code in {200, 404}:
                    ttl = 86400 if url.endswith("dns.json") else 21600
                    _CACHE[key] = (now + ttl, response.status_code, payload)
                return response.status_code, payload

        report = collect("rdap", target, fetch, registrable_domain=registrable)
        for chunk in report_chunks(report):
            self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(chunk), self.__name__, event))

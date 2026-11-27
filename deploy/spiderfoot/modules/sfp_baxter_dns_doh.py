"""BaxterSec: postura DNS exacta mediante el resolvedor público de Google."""
import hashlib
import os
import tempfile

import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

from baxter_passive import collect, report_chunks, serialize_report_chunk


def _combined_ca_bundle(custom_ca):
    """Trust public roots plus the configured institutional CA."""
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


class sfp_baxter_dns_doh(SpiderFootPlugin):
    meta = {
        "name": "BaxterSec DNS DoH (pasivo)",
        "summary": "Consulta registros exactos del objetivo mediante Google Public DNS sin contactar al activo.",
        "flags": [],
        "useCases": ["Passive"],
        "categories": ["DNS"],
    }
    opts = {"ca_bundle": os.getenv("SPIDERFOOT_CA_BUNDLE", "").strip()}
    optdescs = {"ca_bundle": "Ruta PEM opcional de una CA institucional confiable; nunca desactiva la verificación TLS"}

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
            ca_bundle = str(self.opts.get("ca_bundle") or "").strip()
            if ca_bundle and not os.path.isfile(ca_bundle):
                raise FileNotFoundError("El bundle CA configurado no existe")
            response = requests.get(
                url,
                params=params,
                headers={"Accept": "application/dns-json"},
                timeout=(5, 10),
                allow_redirects=False,
                verify=_combined_ca_bundle(ca_bundle),
            )
            try:
                payload = response.json()
            except ValueError:
                payload = None
            return response.status_code, payload

        report = collect("google_dns_doh", target, fetch)
        for chunk in report_chunks(report):
            self.notifyListeners(
                SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(chunk), self.__name__, event)
            )

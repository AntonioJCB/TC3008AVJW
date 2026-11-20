"""BaxterSec: consultas a registros existentes, exclusivamente del objetivo."""
import os
import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from baxter_passive import collect, serialize_report_chunk


class sfp_baxter_shodan(SpiderFootPlugin):
    meta = {"name": "BaxterSec shodan (pasivo)", "summary": "Consulta historial del objetivo sin comprobar servicios activos.", "flags": ["apikey"], "useCases": ["Passive"], "categories": ["Search Engines"]}
    opts = {"api_key": os.getenv("SPIDERFOOT_SHODAN_API_KEY", "")}
    optdescs = {"api_key": "Clave con acceso a Shodan Host; nunca se exporta"}

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.opts = {**type(self).opts, **(userOpts or {})}
        self.done = False

    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    def handleEvent(self, event):
        target = self.getTarget().targetValue
        if self.done or event.data != target:
            return
        self.done = True
        def fetch(url, params):
            response = requests.get(url, params=params, timeout=30, allow_redirects=False)
            try:
                payload = response.json()
            except ValueError:
                payload = None
            return response.status_code, payload
        report = collect("shodan", target, fetch, api_key=self.opts.get("api_key", ""))
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(report), self.__name__, event))

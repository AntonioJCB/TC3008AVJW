"""BaxterSec: consultas a registros existentes, exclusivamente del objetivo."""
import os
import requests
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
from baxter_passive import collect, serialize_report_chunk


class sfp_baxter_internetdb(SpiderFootPlugin):
    meta = {"name": "BaxterSec internetdb (pasivo)", "summary": "Consulta historial del objetivo sin comprobar servicios activos.", "flags": [], "useCases": ["Passive"], "categories": ["Search Engines"]}
    opts = {"use": os.getenv("SPIDERFOOT_INTERNETDB_USE", "disabled")}
    optdescs = {"use": "InternetDB: disabled, noncommercial o licensed (licencia comercial vigente)"}

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
        report = collect("internetdb", target, fetch, internetdb_use=self.opts.get("use", "disabled"))
        self.notifyListeners(SpiderFootEvent("RAW_RIR_DATA", serialize_report_chunk(report), self.__name__, event))

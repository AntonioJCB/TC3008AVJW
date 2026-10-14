import json
from pathlib import Path


class SpiderFootFileCollector:
    name = "spiderfoot_file"

    def __init__(self, path: str):
        self.path = Path(path)

    def collect(self, domain: str) -> list[dict]:
        if not self.path.exists():
            raise FileNotFoundError(f"No existe el archivo: {self.path}")
        with open(self.path, encoding="utf-8") as f:
            events = json.load(f)
        if not isinstance(events, list):
            raise ValueError("El JSON debe ser una lista de eventos")
        return events
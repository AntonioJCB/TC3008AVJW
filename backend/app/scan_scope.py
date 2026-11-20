"""Comprobaciones de alcance explícito para activos IP."""

import ipaddress
import re

from app.osint_normalization import normalizar_dominio


def scope_allows_domain(scope: str, value: str) -> bool:
    normalized = normalizar_dominio(value)
    if normalized is None:
        return False
    host = normalized[0]
    for entry in re.split(r"[\s,;]+", scope):
        token = normalizar_dominio(entry.strip("()[]{}<>\"'.,"))
        if token is None:
            continue
        root, wildcard = token
        if host.endswith(f".{root}") or (host == root and not wildcard):
            return True
    return False


def scope_allows_ip(scope: str, value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for entry in re.split(r"[\s,;]+", scope):
        try:
            network = ipaddress.ip_network(entry.strip("()[]{}<>\"'.,"), strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False

"""Comprobaciones ligeras de un hostname autorizado, sin recorrer enlaces ni IPs ajenas."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.osint_normalization import normalizar_dominio


async def _public_addresses(host: str) -> list[str]:
    records = await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM), timeout=3.0,
    )
    addresses = sorted({ipaddress.ip_address(record[4][0]).compressed for record in records})
    if not addresses or not all(ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("El nombre no resuelve exclusivamente a direcciones públicas")
    return addresses


async def _head(host: str, address: str, port: int, *, tls: bool, timeout: float) -> tuple[int, dict[str, str], dict]:
    context = ssl.create_default_context() if tls else None
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port, ssl=context, server_hostname=host if tls else None, limit=8192),
        timeout=timeout,
    )
    try:
        writer.write(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: BaxterSec/0.1\r\nConnection: close\r\n\r\n".encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        block = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        lines = block.decode("iso-8859-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        headers = {key.strip().lower(): value.strip() for line in lines[1:] if ":" in line
                   for key, value in [line.split(":", 1)]}
        ssl_object = writer.get_extra_info("ssl_object")
        cert = ssl_object.getpeercert() if ssl_object else {}
        return status, headers, cert
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
        except (OSError, TimeoutError):
            pass


async def inspect_host(target: str, timeout: float = 8.0) -> tuple[list[dict], list[str]]:
    normalized = normalizar_dominio(target)
    if normalized is None or normalized[1]:
        raise ValueError("El objetivo web debe ser un hostname concreto")
    host = normalized[0]
    addresses = await _public_addresses(host)
    # Se conecta a la IP resuelta, pero siempre con SNI y Host del nombre autorizado.
    # No se siguen redirecciones ni se consultan rutas adicionales.
    address = addresses[0]
    events: list[dict] = []
    errors: list[str] = []
    try:
        _, _, cert = await _head(host, address, 443, tls=True, timeout=timeout)
        expiry_text = cert.get("notAfter")
        if expiry_text:
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry_text), timezone.utc)
            days = (expiry - datetime.now(timezone.utc)).total_seconds() / 86400
            events.append({"host": host, "check": "tls_verificado", "valid_until": expiry.isoformat(), "days_remaining": round(days, 1)})
            if days <= 14:
                events.append({"host": host, "check": "tls_por_expirar", "valid_until": expiry.isoformat(), "days_remaining": round(days, 1)})
    except ssl.SSLCertVerificationError as error:
        events.append({"host": host, "check": "tls_invalido", "verify_code": getattr(error, "verify_code", None)})
    except (OSError, TimeoutError, ValueError, ssl.SSLError) as error:
        errors.append(f"HTTPS: {type(error).__name__}")

    try:
        status, headers, _ = await _head(host, address, 80, tls=False, timeout=timeout)
        if 200 <= status < 300:
            events.append({"host": host, "check": "http_sin_redireccion", "status": status})
        elif 300 <= status < 400:
            destination = urlsplit(headers.get("location", ""))
            if not (destination.scheme.lower() == "https" and destination.hostname == host
                    and destination.port in {None, 443}):
                errors.append("HTTP: redirección no verificable sin seguir destinos externos")
        elif not 300 <= status < 400:
            errors.append(f"HTTP: estado {status} no permite evaluar la redirección")
    except (OSError, TimeoutError, ValueError) as error:
        errors.append(f"HTTP: {type(error).__name__}; redirección no evaluada")
    checked_at = datetime.now(timezone.utc).isoformat()
    for event in events:
        event.update(validation_mode="active-authorized-v1", checked_at=checked_at)
    return events, errors

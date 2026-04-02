import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_BLOCKED_NETWORKS: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

_ALLOWED_LOOPBACK: ipaddress.IPv4Network = ipaddress.IPv4Network("127.0.0.0/8")


def validate_ollama_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname: str = parsed.hostname or ""
    if not hostname:
        return False

    try:
        port: int | None = parsed.port
    except ValueError:
        return False

    if port is not None and (port < 1 or port > 65535):
        return False

    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True

    try:
        resolved: str = socket.gethostbyname(hostname)
        addr: ipaddress.IPv4Address = ipaddress.IPv4Address(resolved)
    except (socket.gaierror, ValueError):
        return False

    if addr in _ALLOWED_LOOPBACK:
        return True

    for network in _BLOCKED_NETWORKS:
        if addr in network:
            logger.warning("Blocked SSRF attempt to private range: %s -> %s", hostname, resolved)
            return False

    return True

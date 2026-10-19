"""SSRF and transport security guard for Harvey HTTP clients.
Enforces fail-closed socket connection boundaries:
- Rejects loopback, private RFC1918, link-local, cloud metadata, multicast, and reserved IPs.
- Verifies IPv4-mapped IPv6 and raw IPv6 addresses.
- Intercepts at the transport connection boundary to prevent DNS rebinding TOCTOU.
- Verifies redirect targets.
"""

import ipaddress
import logging
import socket
from typing import Callable, Iterable, Optional

import httpcore
import httpx

logger = logging.getLogger("harvey.security.ssrf")


class SSRFBlockedError(Exception):
    """Raised when an outbound HTTP request targets a prohibited host or IP address."""


def is_safe_ip(ip_str: str) -> bool:
    """Return True if the IP address is globally routable and not in private/reserved ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Deep inspection of IPv6 encodings (IPv4-mapped, IPv4-compatible, 6to4, Teredo)
        if ip.version == 6:
            if ip.ipv4_mapped:
                return is_safe_ip(str(ip.ipv4_mapped))
            # IPv4-compatible IPv6 (deprecated but recognized, starts with 12 zero bytes)
            if ip.packed.startswith(b"\x00" * 12) and ip != ipaddress.IPv6Address("::"):
                return is_safe_ip(str(ipaddress.IPv4Address(ip.packed[12:])))
            if ip.sixtofour:
                return is_safe_ip(str(ip.sixtofour))
            if ip.teredo:
                server, client = ip.teredo
                if not is_safe_ip(str(server)) or not is_safe_ip(str(client)):
                    return False
        if not ip.is_global:
            return False
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False
        return True
    except ValueError:
        return False


def validate_destination_address(host: str, port: int, resolver: Optional[Callable] = None) -> str:
    """Resolve host and assert every resolved IP is a safe, globally routable address.
    Returns the first verified IP address for immediate connection.
    """
    # First check if host is an IP literal
    try:
        ip = ipaddress.ip_address(host)
        if not is_safe_ip(str(ip)):
            raise SSRFBlockedError(f"SSRF blocked: IP literal {host} is in prohibited range")
        return str(ip)
    except ValueError:
        pass

    # Reject localhost or loopback aliases
    host_clean = host.strip(".").lower()
    if host_clean in ("localhost", "local", "ip6-localhost", "ip6-loopback") or host_clean.endswith(".local"):
        raise SSRFBlockedError(f"SSRF blocked: loopback hostname {host}")

    dns_func = resolver or socket.getaddrinfo
    try:
        addr_info = dns_func(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise httpcore.ConnectError(f"DNS resolution failed for {host}: {e}") from e

    if not addr_info:
        raise httpcore.ConnectError(f"No DNS records returned for {host}")

    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_cand = sockaddr[0]
        if not is_safe_ip(ip_cand):
            raise SSRFBlockedError(
                f"SSRF blocked: destination host {host} resolved to prohibited IP {ip_cand}"
            )

    # Return the first safe resolved IP
    return addr_info[0][4][0]


class SSRFSafeNetworkBackend(httpcore.AnyIOBackend):
    """httpcore NetworkBackend that validates DNS and binds to the verified IP directly."""

    def __init__(self, resolver: Optional[Callable] = None):
        super().__init__()
        self.resolver = resolver

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Optional[Iterable] = None,
    ):
        verified_ip = validate_destination_address(host, port, self.resolver)
        # Connect directly to the verified safe IP to defeat DNS rebinding TOCTOU
        return await super().connect_tcp(
            host=verified_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class SSRFSafeTransport(httpx.AsyncHTTPTransport):
    """httpx AsyncTransport wrapped with SSRF connection boundary verification."""

    def __init__(self, resolver: Optional[Callable] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pool._network_backend = SSRFSafeNetworkBackend(resolver=resolver)

SSRFSafeBackend = SSRFSafeNetworkBackend

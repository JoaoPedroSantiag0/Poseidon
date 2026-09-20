"""SSRF (Server-Side Request Forgery) Defense Firewall & URL Validator."""
import ipaddress
import socket
from urllib.parse import urlparse

# Private, Reserved and Cloud Metadata IPv4 & IPv6 networks to block
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("::1/128"),              # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-Local
]


def is_safe_ip(ip_str: str) -> bool:
    """Checks whether an IP address is safe for outbound communication."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
        for net in DISALLOWED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def validate_outbound_url(url: str) -> str:
    """Validates an outbound URL to prevent SSRF against internal or cloud metadata infrastructure.

    Raises ValueError if URL scheme is not http/https or target IP resolves to private/reserved networks.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname or IP address.")

    # Check direct IP addresses
    try:
        if not is_safe_ip(hostname):
            raise ValueError(f"Target host '{hostname}' resides in a restricted private, link-local, or loopback network.")
        return url
    except ValueError:
        # Not a raw IP literal, proceed to DNS resolution check
        pass

    # Resolve hostname to verify destination IP
    try:
        # getaddrinfo resolves both IPv4 and IPv6
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            resolved_ip = entry[4][0]
            if not is_safe_ip(resolved_ip):
                raise ValueError(
                    f"Host '{hostname}' resolves to restricted IP address '{resolved_ip}'. Outbound request blocked."
                )
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve host '{hostname}': {exc!s}") from exc

    return url


# Convenient alias
validate_destination = validate_outbound_url


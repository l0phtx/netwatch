"""Host discovery with ARP requests."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor

from netwatch.models import Device
from netwatch.vendor import lookup_vendor

log = logging.getLogger(__name__)

MAX_HOSTS = 65_536


class DiscoveryError(RuntimeError):
    """Raised when a network sweep cannot run."""


def validate_network(cidr: str) -> ipaddress.IPv4Network:
    """Parse a CIDR string and reject networks too large to sweep."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise DiscoveryError(f"invalid network {cidr!r}: {exc}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise DiscoveryError("only IPv4 networks are supported (ARP is IPv4-only)")
    if network.num_addresses > MAX_HOSTS:
        raise DiscoveryError(f"{cidr} is too large; use a /16 or smaller")
    return network


def require_root() -> None:
    """ARP sweeps need raw sockets, which need root (or CAP_NET_RAW)."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise DiscoveryError("ARP discovery needs root privileges; run with sudo")


def arp_sweep(
    network: ipaddress.IPv4Network,
    iface: str | None = None,
    timeout: float = 2.0,
    retries: int = 1,
) -> list[Device]:
    """Broadcast ARP who-has requests and return every host that answers."""
    # Imported lazily: loading Scapy is slow and not needed for every command.
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    log.debug("sending ARP sweep to %s (iface=%s)", network, iface or "auto")
    answered, _ = srp(packet, iface=iface, timeout=timeout, retry=retries, verbose=False)

    devices: dict[str, Device] = {}
    for _, reply in answered:
        mac = reply.hwsrc.lower()
        devices[mac] = Device(mac=mac, ip=reply.psrc, vendor=lookup_vendor(mac))
    return sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip))


def resolve_hostnames(devices: list[Device], workers: int = 32) -> None:
    """Fill in reverse-DNS names in place. Failures are ignored."""

    def resolve(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return None

    if not devices:
        return
    with ThreadPoolExecutor(max_workers=min(workers, len(devices))) as pool:
        for device, name in zip(devices, pool.map(resolve, (d.ip for d in devices)), strict=True):
            device.hostname = name

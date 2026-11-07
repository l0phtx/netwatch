"""Concurrent TCP connect port scanning."""

from __future__ import annotations

import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

# Ports most often found open on office and home networks.
# fmt: off
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 515, 548, 554,
    631, 993, 995, 1433, 1883, 3306, 3389, 5000, 5353, 5432, 5900, 6379,
    8000, 8008, 8080, 8443, 8888, 9100, 27017,
)
# fmt: on


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec such as ``"22,80,8000-8100"`` or ``"common"``."""
    spec = spec.strip().lower()
    if spec in ("", "none"):
        return []
    if spec == "common":
        return list(COMMON_PORTS)

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            start, end = int(low), int(high)
            if start > end:
                raise ValueError(f"invalid port range {part!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    invalid = [p for p in ports if not 1 <= p <= 65535]
    if invalid:
        raise ValueError(f"ports out of range 1-65535: {sorted(invalid)[:5]}")
    return sorted(ports)


def is_port_open(ip: str, port: int, timeout: float) -> bool:
    """Try a full TCP handshake; True if the port accepts the connection."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_hosts(
    ips: list[str],
    ports: list[int],
    timeout: float = 0.5,
    workers: int = 200,
) -> dict[str, list[int]]:
    """Scan every (ip, port) pair concurrently and return open ports per IP."""
    results: dict[str, list[int]] = {ip: [] for ip in ips}
    targets = [(ip, port) for ip in ips for port in ports]
    if not targets:
        return results

    found: dict[str, list[int]] = defaultdict(list)
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        states = pool.map(lambda t: is_port_open(t[0], t[1], timeout), targets)
        for (ip, port), is_open in zip(targets, states, strict=True):
            if is_open:
                found[ip].append(port)

    for ip, open_ports in found.items():
        results[ip] = sorted(open_ports)
    return results


def service_name(port: int) -> str:
    """Best-effort service name for a TCP port (e.g. 22 -> ssh)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

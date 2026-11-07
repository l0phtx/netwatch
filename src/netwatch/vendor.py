"""MAC address vendor (OUI) lookup."""

from __future__ import annotations

from functools import lru_cache


def is_locally_administered(mac: str) -> bool:
    """True when the MAC has the locally-administered bit set.

    Phones and laptops use these randomized addresses for privacy, so they
    never match a vendor in the IEEE registry.
    """
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0b10)


@lru_cache(maxsize=1024)
def lookup_vendor(mac: str) -> str:
    """Return the hardware vendor for a MAC address, or a short explanation."""
    mac = mac.lower()
    if is_locally_administered(mac):
        return "Private (randomized MAC)"
    try:
        from scapy.config import conf
    except ImportError:  # pragma: no cover - scapy is a hard dependency
        return "Unknown"
    if conf.manufdb is None:
        return "Unknown"
    name = conf.manufdb._get_manuf(mac)
    # Scapy echoes the MAC back when the OUI is not in its database.
    if not name or name.lower() == mac:
        return "Unknown"
    return name

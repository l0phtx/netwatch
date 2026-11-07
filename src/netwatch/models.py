"""Data models shared across NetWatch modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Device:
    """A host observed on the network, identified by its MAC address."""

    mac: str
    ip: str
    vendor: str = "Unknown"
    hostname: str | None = None
    open_ports: list[int] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    trusted: bool = False
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ScanDiff:
    """Changes between a fresh scan and the saved inventory."""

    new: list[Device] = field(default_factory=list)
    ip_changed: list[tuple[Device, str]] = field(default_factory=list)
    ports_changed: list[tuple[Device, list[int]]] = field(default_factory=list)
    missing: list[Device] = field(default_factory=list)

    @property
    def unknown_new(self) -> list[Device]:
        """New devices that are not marked as trusted."""
        return [d for d in self.new if not d.trusted]

    def has_changes(self) -> bool:
        return bool(self.new or self.ip_changed or self.ports_changed or self.missing)

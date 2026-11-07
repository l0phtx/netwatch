"""Persistent device inventory and change detection."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from netwatch.models import Device, ScanDiff

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Inventory:
    """Known devices keyed by MAC address, stored as a JSON file."""

    def __init__(self, path: Path, devices: dict[str, Device] | None = None) -> None:
        self.path = path
        self.devices: dict[str, Device] = devices or {}

    @classmethod
    def load(cls, path: Path) -> Inventory:
        if not path.exists():
            return cls(path)
        data = json.loads(path.read_text(encoding="utf-8"))
        devices = {d["mac"]: Device.from_dict(d) for d in data.get("devices", [])}
        return cls(path, devices)

    def save(self) -> None:
        """Write atomically so a crash mid-write never corrupts the inventory."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": SCHEMA_VERSION,
            "updated": utc_now(),
            "devices": [d.to_dict() for d in sorted(self.devices.values(), key=lambda d: d.mac)],
        }
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".netwatch-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
                fh.write("\n")
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def diff(self, scanned: list[Device], ports_scanned: bool = True) -> ScanDiff:
        """Compare a scan with the inventory without changing anything."""
        result = ScanDiff()
        seen = {d.mac for d in scanned}
        for device in scanned:
            known = self.devices.get(device.mac)
            if known is None:
                result.new.append(device)
                continue
            if known.ip != device.ip:
                result.ip_changed.append((device, known.ip))
            if ports_scanned and known.open_ports != device.open_ports:
                result.ports_changed.append((device, known.open_ports))
        result.missing = [d for mac, d in self.devices.items() if mac not in seen]
        return result

    def update(self, scanned: list[Device], ports_scanned: bool = True, trust_new: bool = False) -> ScanDiff:
        """Merge a scan into the inventory and return what changed."""
        now = utc_now()
        result = self.diff(scanned, ports_scanned=ports_scanned)
        for device in scanned:
            known = self.devices.get(device.mac)
            if known is None:
                device.first_seen = now
                device.last_seen = now
                device.trusted = trust_new
                self.devices[device.mac] = device
                continue
            known.ip = device.ip
            known.vendor = device.vendor
            known.hostname = device.hostname or known.hostname
            known.last_seen = now
            if ports_scanned:
                known.open_ports = device.open_ports
            # Callers render the merged record, so carry trust and label over.
            device.trusted = known.trusted
            device.label = known.label
            device.first_seen = known.first_seen
            device.last_seen = now
        return result

    def trust(self, mac: str, label: str | None = None) -> Device:
        device = self._get(mac)
        device.trusted = True
        if label is not None:
            device.label = label
        return device

    def untrust(self, mac: str) -> Device:
        device = self._get(mac)
        device.trusted = False
        return device

    def remove(self, mac: str) -> Device:
        device = self._get(mac)
        del self.devices[device.mac]
        return device

    def _get(self, mac: str) -> Device:
        key = normalize_mac(mac)
        try:
            return self.devices[key]
        except KeyError:
            raise KeyError(f"no device with MAC {key} in {self.path}") from None


def normalize_mac(mac: str) -> str:
    """Accept aa-bb-cc..., AABB.CCDD.EEFF or aa:bb:... and return aa:bb:cc:dd:ee:ff."""
    digits = "".join(c for c in mac.lower() if c in "0123456789abcdef")
    if len(digits) != 12:
        raise ValueError(f"invalid MAC address {mac!r}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))

"""Rendering scan results as tables, JSON and CSV."""

from __future__ import annotations

import csv
import io
import json

from netwatch.models import Device, ScanDiff

COLUMNS = ("IP", "MAC", "VENDOR", "HOSTNAME", "OPEN PORTS", "STATUS")


def _status(device: Device, new_macs: set[str]) -> str:
    if device.mac in new_macs:
        return "NEW" if not device.trusted else "new (trusted)"
    return "trusted" if device.trusted else "known"


def _row(device: Device, new_macs: set[str]) -> tuple[str, ...]:
    return (
        device.ip,
        device.mac,
        device.vendor,
        device.label or device.hostname or "-",
        ",".join(map(str, device.open_ports)) or "-",
        _status(device, new_macs),
    )


def render_table(devices: list[Device], diff: ScanDiff | None = None) -> str:
    """Plain-text table that stays readable over SSH and in log files."""
    new_macs = {d.mac for d in diff.new} if diff else set()
    rows = [COLUMNS, *(_row(d, new_macs) for d in devices)]
    widths = [max(len(r[i]) for r in rows) for i in range(len(COLUMNS))]
    lines = ["  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def render_summary(devices: list[Device], diff: ScanDiff) -> str:
    parts = [f"{len(devices)} devices up"]
    if diff.new:
        parts.append(f"{len(diff.new)} new ({len(diff.unknown_new)} unknown)")
    if diff.ip_changed:
        parts.append(f"{len(diff.ip_changed)} changed IP")
    if diff.ports_changed:
        parts.append(f"{len(diff.ports_changed)} changed ports")
    if diff.missing:
        parts.append(f"{len(diff.missing)} not seen")
    return ", ".join(parts)


def render_json(devices: list[Device]) -> str:
    return json.dumps([d.to_dict() for d in devices], indent=2)


def render_csv(devices: list[Device]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ip", "mac", "vendor", "hostname", "label", "open_ports", "trusted", "first_seen", "last_seen"])
    for d in devices:
        writer.writerow(
            [
                d.ip,
                d.mac,
                d.vendor,
                d.hostname or "",
                d.label or "",
                " ".join(map(str, d.open_ports)),
                d.trusted,
                d.first_seen or "",
                d.last_seen or "",
            ]
        )
    return buffer.getvalue()

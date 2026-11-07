"""Alert delivery for new or changed devices."""

from __future__ import annotations

import json
import logging
import urllib.request
from urllib.error import URLError

from netwatch.models import ScanDiff

log = logging.getLogger(__name__)


def build_message(diff: ScanDiff, network: str) -> str | None:
    """Return a human-readable alert, or None if there is nothing to report."""
    lines: list[str] = []
    for d in diff.unknown_new:
        lines.append(f"NEW unknown device {d.ip} ({d.mac}, {d.vendor})")
    for d, old_ip in diff.ip_changed:
        if not d.trusted:
            lines.append(f"IP changed for untrusted device {d.mac}: {old_ip} -> {d.ip}")
    for d, old_ports in diff.ports_changed:
        opened = sorted(set(d.open_ports) - set(old_ports))
        if opened:
            lines.append(f"New open ports on {d.ip} ({d.label or d.mac}): {', '.join(map(str, opened))}")
    if not lines:
        return None
    return f"NetWatch alert for {network}:\n" + "\n".join(f"- {line}" for line in lines)


def send_webhook(url: str, message: str, timeout: float = 10.0) -> bool:
    """POST ``{"text": message}``; works with Slack, Google Chat and Mattermost."""
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("webhook URL must start with http:// or https://")
    body = json.dumps({"text": message}).encode()
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        data=body,
        headers={"Content-Type": "application/json; charset=UTF-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            status: int = response.status
            return 200 <= status < 300
    except (URLError, TimeoutError) as exc:
        log.warning("webhook delivery failed: %s", exc)
        return False

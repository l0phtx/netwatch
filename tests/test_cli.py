import json

import pytest

from netwatch import cli
from netwatch.models import Device


@pytest.fixture
def fake_network(monkeypatch):
    devices = [
        Device(mac="00:50:56:00:00:01", ip="192.168.1.1", vendor="VMware, Inc."),
        Device(mac="00:50:56:00:00:02", ip="192.168.1.2", vendor="VMware, Inc."),
    ]
    monkeypatch.setattr(cli, "require_root", lambda: None)
    monkeypatch.setattr(cli, "arp_sweep", lambda *a, **k: [Device(**d.to_dict()) for d in devices])
    monkeypatch.setattr(cli, "scan_hosts", lambda ips, *a, **k: {ip: [22] if ip.endswith(".1") else [] for ip in ips})
    monkeypatch.setattr(cli, "resolve_hostnames", lambda devs: None)
    return devices


def test_scan_then_trust_then_rescan(tmp_path, fake_network, capsys):
    db = str(tmp_path / "inv.json")
    assert cli.main(["--db", db, "scan", "192.168.1.0/24", "--fail-on-unknown"]) == cli.EXIT_UNKNOWN_DEVICE
    out = capsys.readouterr().out
    assert "2 devices up, 2 new (2 unknown)" in out

    assert cli.main(["--db", db, "trust", "00:50:56:00:00:01", "--label", "Gateway"]) == 0
    assert cli.main(["--db", db, "trust", "00:50:56:00:00:02"]) == 0
    capsys.readouterr()

    assert cli.main(["--db", db, "scan", "192.168.1.0/24", "--fail-on-unknown"]) == 0
    out = capsys.readouterr().out
    assert "Gateway" in out and "2 devices up" in out and "new" not in out.split("\n")[-2]


def test_scan_json_output_file(tmp_path, fake_network, capsys):
    out_file = tmp_path / "scan.json"
    args = ["--db", str(tmp_path / "inv.json"), "scan", "192.168.1.0/24", "-f", "json", "-o", str(out_file)]
    assert cli.main(args) == 0
    data = json.loads(out_file.read_text())
    assert data[0]["open_ports"] == [22]


def test_devices_unknown_filter(tmp_path, fake_network, capsys):
    db = str(tmp_path / "inv.json")
    cli.main(["--db", db, "scan", "192.168.1.0/24", "--ports", "none"])
    cli.main(["--db", db, "trust", "00:50:56:00:00:01"])
    capsys.readouterr()

    assert cli.main(["--db", db, "devices", "--unknown"]) == 0
    out = capsys.readouterr().out
    assert "192.168.1.2" in out and "192.168.1.1 " not in out


def test_unknown_mac_is_an_error(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "inv.json"), "trust", "00:11:22:33:44:55"]) == 1


def test_bad_network_is_an_error(tmp_path):
    assert cli.main(["--db", str(tmp_path / "inv.json"), "scan", "10.0.0.0/8"]) == 1


def test_watch_rejects_tiny_interval(tmp_path):
    assert cli.main(["--db", str(tmp_path / "inv.json"), "watch", "192.168.1.0/24", "--interval", "1"]) == 1

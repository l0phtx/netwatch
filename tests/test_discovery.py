import ipaddress
from types import SimpleNamespace

import pytest

from netwatch import discovery
from netwatch.discovery import DiscoveryError, arp_sweep, validate_network
from netwatch.vendor import is_locally_administered, lookup_vendor


def test_validate_network_accepts_host_bits():
    assert validate_network("192.168.1.77/24") == ipaddress.ip_network("192.168.1.0/24")


@pytest.mark.parametrize("cidr", ["nonsense", "10.0.0.0/8", "fe80::/64"])
def test_validate_network_rejects(cidr):
    with pytest.raises(DiscoveryError):
        validate_network(cidr)


def test_require_root(monkeypatch):
    monkeypatch.setattr(discovery.os, "geteuid", lambda: 1000)
    with pytest.raises(DiscoveryError, match="root"):
        discovery.require_root()
    monkeypatch.setattr(discovery.os, "geteuid", lambda: 0)
    discovery.require_root()


def test_arp_sweep_parses_and_sorts_replies(monkeypatch):
    replies = [
        (None, SimpleNamespace(hwsrc="00:50:56:AA:BB:CC", psrc="192.168.1.20")),
        (None, SimpleNamespace(hwsrc="02:11:22:33:44:55", psrc="192.168.1.3")),
        (None, SimpleNamespace(hwsrc="00:50:56:aa:bb:cc", psrc="192.168.1.20")),
    ]
    monkeypatch.setattr("scapy.sendrecv.srp", lambda *a, **k: (replies, []))

    devices = arp_sweep(ipaddress.ip_network("192.168.1.0/24"))
    assert [d.ip for d in devices] == ["192.168.1.3", "192.168.1.20"]
    assert devices[0].vendor == "Private (randomized MAC)"
    assert devices[1].mac == "00:50:56:aa:bb:cc"


def test_resolve_hostnames(monkeypatch, make_device):
    def fake_lookup(ip):
        if ip == "192.168.1.10":
            return ("printer.lan", [], [ip])
        raise OSError("no PTR")

    monkeypatch.setattr(discovery.socket, "gethostbyaddr", fake_lookup)
    devices = [make_device(), make_device(mac="aa:00:00:00:00:02", ip="192.168.1.11")]
    discovery.resolve_hostnames(devices)
    assert [d.hostname for d in devices] == ["printer.lan", None]


def test_locally_administered():
    assert is_locally_administered("02:00:00:00:00:00")
    assert is_locally_administered("da:a1:19:00:00:00")
    assert not is_locally_administered("00:50:56:00:00:00")


def test_lookup_vendor_known_oui():
    assert "VMware" in lookup_vendor("00:50:56:c0:00:08")

import json

import pytest

from netwatch.inventory import Inventory, normalize_mac


def test_first_scan_marks_everything_new(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    diff = inv.update([make_device(), make_device(mac="aa:00:00:00:00:02", ip="192.168.1.11")])

    assert len(diff.new) == 2
    assert len(diff.unknown_new) == 2
    assert all(d.first_seen for d in inv.devices.values())


def test_trust_new_builds_baseline(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    diff = inv.update([make_device()], trust_new=True)

    assert diff.new and not diff.unknown_new
    assert inv.devices["aa:00:00:00:00:01"].trusted


def test_known_device_is_not_new(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    inv.update([make_device()])
    diff = inv.update([make_device()])

    assert not diff.new
    assert not diff.has_changes()


def test_detects_ip_change_and_missing(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    inv.update([make_device(), make_device(mac="aa:00:00:00:00:02", ip="192.168.1.11")])
    diff = inv.update([make_device(ip="192.168.1.99")])

    assert [(d.mac, old) for d, old in diff.ip_changed] == [("aa:00:00:00:00:01", "192.168.1.10")]
    assert [d.mac for d in diff.missing] == ["aa:00:00:00:00:02"]
    assert inv.devices["aa:00:00:00:00:01"].ip == "192.168.1.99"


def test_detects_port_change_only_when_ports_scanned(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    inv.update([make_device(open_ports=[22])])

    assert not inv.update([make_device(open_ports=[])], ports_scanned=False).ports_changed
    assert inv.devices["aa:00:00:00:00:01"].open_ports == [22]

    diff = inv.update([make_device(open_ports=[22, 3389])])
    assert diff.ports_changed[0][1] == [22]


def test_scan_result_carries_trust_and_label(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    inv.update([make_device()])
    inv.trust("AA-00-00-00-00-01", label="Printer")

    scanned = make_device()
    inv.update([scanned])
    assert scanned.trusted and scanned.label == "Printer"


def test_save_and_load_roundtrip(tmp_path, make_device):
    path = tmp_path / "sub" / "inv.json"
    inv = Inventory(path)
    inv.update([make_device(open_ports=[80])])
    inv.trust("aa:00:00:00:00:01", "NAS")
    inv.save()

    data = json.loads(path.read_text())
    assert data["schema"] == 1
    loaded = Inventory.load(path)
    device = loaded.devices["aa:00:00:00:00:01"]
    assert device.label == "NAS" and device.trusted and device.open_ports == [80]
    assert not list(path.parent.glob(".netwatch-*"))


def test_load_missing_file_is_empty(tmp_path):
    assert Inventory.load(tmp_path / "nope.json").devices == {}


def test_untrust_and_remove(tmp_path, make_device):
    inv = Inventory(tmp_path / "inv.json")
    inv.update([make_device()], trust_new=True)
    assert not inv.untrust("aa:00:00:00:00:01").trusted
    inv.remove("aa:00:00:00:00:01")
    assert inv.devices == {}
    with pytest.raises(KeyError):
        inv.remove("aa:00:00:00:00:01")


@pytest.mark.parametrize(
    "raw",
    ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "aabbccddeeff"],
)
def test_normalize_mac(raw):
    assert normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_mac("not-a-mac")

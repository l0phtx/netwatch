import json

import pytest

from netwatch import alerts
from netwatch.models import ScanDiff
from netwatch.report import render_csv, render_json, render_summary, render_table


def test_no_message_when_only_trusted_devices(make_device):
    diff = ScanDiff(new=[make_device(trusted=True)])
    assert alerts.build_message(diff, "192.168.1.0/24") is None


def test_message_lists_unknown_and_opened_ports(make_device):
    rogue = make_device(mac="aa:00:00:00:00:09", ip="192.168.1.50", vendor="Raspberry Pi")
    nas = make_device(ip="192.168.1.20", open_ports=[22, 445], label="NAS", trusted=True)
    diff = ScanDiff(new=[rogue], ports_changed=[(nas, [22])])

    message = alerts.build_message(diff, "192.168.1.0/24")
    assert "NEW unknown device 192.168.1.50" in message
    assert "Raspberry Pi" in message
    assert "New open ports on 192.168.1.20 (NAS): 445" in message


def test_closed_ports_do_not_alert(make_device):
    device = make_device(open_ports=[22])
    assert alerts.build_message(ScanDiff(ports_changed=[(device, [22, 80])]), "net") is None


def test_webhook_rejects_non_http():
    with pytest.raises(ValueError):
        alerts.send_webhook("file:///etc/passwd", "hi")


def test_webhook_posts_json(monkeypatch):
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data)
        captured["method"] = request.get_method()
        return Response()

    monkeypatch.setattr(alerts.urllib.request, "urlopen", fake_urlopen)
    assert alerts.send_webhook("https://chat.example.com/hook", "hello")
    assert captured == {"body": {"text": "hello"}, "method": "POST"}


def test_table_marks_new_devices(make_device):
    known = make_device(trusted=True, label="Router", open_ports=[53, 80])
    new = make_device(mac="aa:00:00:00:00:02", ip="192.168.1.11")
    table = render_table([known, new], ScanDiff(new=[new]))

    lines = table.splitlines()
    assert lines[0].startswith("IP")
    assert "Router" in lines[2] and "53,80" in lines[2] and "trusted" in lines[2]
    assert lines[3].endswith("NEW")


def test_summary(make_device):
    devices = [make_device()]
    diff = ScanDiff(new=devices, missing=[make_device(mac="aa:00:00:00:00:02")])
    assert render_summary(devices, diff) == "1 devices up, 1 new (1 unknown), 1 not seen"


def test_json_and_csv(make_device):
    devices = [make_device(open_ports=[22, 80])]
    assert json.loads(render_json(devices))[0]["open_ports"] == [22, 80]
    csv_text = render_csv(devices)
    assert csv_text.splitlines()[1].startswith("192.168.1.10,aa:00:00:00:00:01,Acme")

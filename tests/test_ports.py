import socket
import threading

import pytest

from netwatch.ports import COMMON_PORTS, is_port_open, parse_ports, scan_hosts, service_name


@pytest.fixture
def listening_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    stop = threading.Event()

    def accept():
        server.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except OSError:
                continue

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    yield server.getsockname()[1]
    stop.set()
    thread.join()
    server.close()


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("22", [22]),
        ("80,22,80", [22, 80]),
        ("8000-8002, 22", [22, 8000, 8001, 8002]),
        ("none", []),
        ("", []),
    ],
)
def test_parse_ports(spec, expected):
    assert parse_ports(spec) == expected


def test_parse_ports_common():
    assert parse_ports("common") == list(COMMON_PORTS)


@pytest.mark.parametrize("spec", ["0", "65536", "100-10", "abc", "1-2-3"])
def test_parse_ports_rejects_invalid(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_is_port_open(listening_port):
    assert is_port_open("127.0.0.1", listening_port, timeout=1)
    assert not is_port_open("127.0.0.1", closed_port(), timeout=1)


def test_scan_hosts(listening_port):
    closed = closed_port()
    result = scan_hosts(["127.0.0.1"], [closed, listening_port], timeout=1)
    assert result == {"127.0.0.1": [listening_port]}


def test_scan_hosts_without_ports():
    assert scan_hosts(["10.0.0.1"], []) == {"10.0.0.1": []}


def test_service_name():
    assert service_name(22) == "ssh"
    assert service_name(1) in ("tcpmux", "unknown")

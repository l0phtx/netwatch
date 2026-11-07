import pytest

from netwatch.models import Device


@pytest.fixture
def make_device():
    def factory(mac="aa:00:00:00:00:01", ip="192.168.1.10", **kwargs):
        kwargs.setdefault("vendor", "Acme")
        return Device(mac=mac, ip=ip, **kwargs)

    return factory

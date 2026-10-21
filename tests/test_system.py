from contextlib import nullcontext
from types import SimpleNamespace

import psutil
import pytest

from deeptrace import system_inspect
from deeptrace.errors import DeepTraceError


def test_host_report_degrades_when_socket_table_is_unavailable(monkeypatch):
    monkeypatch.setattr(system_inspect.psutil, "net_connections", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("blocked")))
    report = system_inspect.host_report()
    assert report["listening_ports"] == []
    assert report["listening_ports_note"] == "unavailable: blocked"


class FakeProcess:
    pid = 321

    def oneshot(self):
        return nullcontext()

    def ppid(self):
        return 12

    def name(self):
        return "python.exe"

    def exe(self):
        return "C:\\Python\\python.exe"

    def cmdline(self):
        return ["python", "worker.py"]

    def username(self):
        return "tester"

    def create_time(self):
        return 1_700_000_000

    def status(self):
        return "running"

    def children(self, recursive=False):
        return [SimpleNamespace(pid=400, name=lambda: "child.exe")]

    def net_connections(self, kind="inet"):
        return [SimpleNamespace(laddr=SimpleNamespace(ip="127.0.0.1", port=5000), raddr=SimpleNamespace(ip="192.0.2.1", port=443), status="ESTABLISHED")]


def _use_fake_process(monkeypatch, process):
    monkeypatch.setattr(system_inspect.psutil, "Process", lambda pid: process)
    monkeypatch.setattr(system_inspect, "_native_process", lambda pid: {"native_note": "test"})


def test_process_report_success(monkeypatch):
    _use_fake_process(monkeypatch, FakeProcess())
    report = system_inspect.process_report(321)
    assert report["name"] == "python.exe"
    assert report["executable"] == "C:\\Python\\python.exe"
    assert report["children"] == [{"pid": 400, "name": "child.exe"}]
    assert report["connections"][0]["remote"] == "192.0.2.1:443"


@pytest.mark.parametrize(
    ("method", "field"),
    [("exe", "executable"), ("username", "username")],
)
def test_process_report_marks_denied_fields_unavailable(monkeypatch, method, field):
    process = FakeProcess()
    setattr(process, method, lambda: (_ for _ in ()).throw(psutil.AccessDenied(pid=321)))
    _use_fake_process(monkeypatch, process)
    report = system_inspect.process_report(321)
    assert report[field] == "unavailable: access denied"
    assert report["name"] == "python.exe"


def test_process_report_marks_denied_connections_unavailable(monkeypatch):
    process = FakeProcess()
    process.net_connections = lambda kind="inet": (_ for _ in ()).throw(psutil.AccessDenied(pid=321))
    _use_fake_process(monkeypatch, process)
    report = system_inspect.process_report(321)
    assert report["connections"] == "unavailable: access denied"
    assert report["command_line"] == ["python", "worker.py"]


def test_process_report_cleanly_reports_disappearance(monkeypatch):
    process = FakeProcess()
    process.name = lambda: (_ for _ in ()).throw(psutil.NoSuchProcess(pid=321))
    _use_fake_process(monkeypatch, process)
    with pytest.raises(DeepTraceError, match="process 321 does not exist"):
        system_inspect.process_report(321)

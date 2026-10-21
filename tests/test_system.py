from deeptrace import system_inspect


def test_host_report_degrades_when_socket_table_is_unavailable(monkeypatch):
    monkeypatch.setattr(system_inspect.psutil, "net_connections", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("blocked")))
    report = system_inspect.host_report()
    assert report["listening_ports"] == []
    assert report["listening_ports_note"] == "unavailable: blocked"

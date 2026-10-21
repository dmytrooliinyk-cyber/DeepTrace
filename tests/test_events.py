import json
from datetime import datetime, timezone

from deeptrace.events import Event, correlate, load_events, normalize_json, normalize_text


def test_linux_ssh_normalization():
    event = normalize_text("Oct 20 10:00:00 web01 sshd[12]: Failed password for invalid user root from 192.0.2.50 port 5555 ssh2", year=2026)
    assert event.event_type == "ssh_auth_failure"
    assert event.username == "root"
    assert event.source_ip == "192.0.2.50"


def test_sysmon_like_normalization():
    event = normalize_json({"UtcTime": "2026-10-20T10:01:00Z", "EventID": 1, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ProcessId": "42"})
    assert event.event_type == "process_start"
    assert event.process_name == "powershell.exe"
    assert event.pid == 42


def test_timeline_sorting_and_unknown_retention(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('\n'.join([json.dumps({"timestamp": "2026-10-20T10:02:00Z", "event_type": "later"}), "unparsed record", json.dumps({"timestamp": "2026-10-20T10:01:00Z", "event_type": "earlier"})]), encoding="utf-8")
    events = load_events(path)
    assert events[0].event_type == "unknown"
    assert events[1].event_type == "earlier"
    assert events[2].event_type == "later"
    assert events[0].raw_event == "unparsed record"


def test_correlations():
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        Event(t, "sysmon", "process_start", process_name="powershell.exe"),
        Event(t, "sysmon", "network_connection", destination_ip="198.51.100.9"),
        Event(t, "sysmon", "file_create", path="C:\\Users\\demo\\AppData\\Local\\Temp\\stage.exe"),
        Event(t, "sysmon", "process_start", process_name="stage.exe"),
    ]
    findings = correlate(events)
    assert any(finding.risk == "High" for finding in findings)
    failures = [Event(t, "linux-auth", "ssh_auth_failure", username="admin", source_ip="192.0.2.4") for _ in range(3)]
    assert correlate(failures)[0].name == "Repeated SSH authentication failures"



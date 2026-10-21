import json
from datetime import datetime, timezone

import pytest

from deeptrace.events import Event, correlate, load_events, normalize_json, normalize_text, parse_timestamp


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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-21T10:00:00Z", "2026-10-21T10:00:00+00:00"),
        ("2026-10-21T12:00:00+02:00", "2026-10-21T10:00:00+00:00"),
        ("2026-10-21T04:30:00-05:30", "2026-10-21T10:00:00+00:00"),
        ("2026-10-21T10:00:00", "2026-10-21T10:00:00+00:00"),
        (0, "1970-01-01T00:00:00+00:00"),
    ],
)
def test_timestamp_normalization_to_utc(value, expected):
    assert parse_timestamp(value).isoformat() == expected


def _execution_chain(*, network_host="lab", network_pid=100, network_process="powershell.exe", launch_name="stage.exe", network_delay=1):
    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    return [
        Event(start, "sysmon", "process_start", hostname="lab", process_name="powershell.exe", pid=100),
        Event(start.replace(minute=start.minute + network_delay), "sysmon", "network_connection", hostname=network_host, destination_ip="198.51.100.9", process_name=network_process, pid=network_pid),
        Event(start.replace(minute=start.minute + network_delay, second=10), "sysmon", "file_create", hostname="lab", process_name="powershell.exe", pid=100, path="C:\\Temp\\stage.exe"),
        Event(start.replace(minute=start.minute + network_delay, second=20), "sysmon", "process_start", hostname="lab", process_name=launch_name, pid=200),
    ]


def _has_high_chain(events):
    return any(finding.risk == "High" for finding in correlate(events))


def test_contextual_execution_chain_still_triggers():
    assert _has_high_chain(_execution_chain())


def test_execution_chain_rejects_different_hosts():
    assert not _has_high_chain(_execution_chain(network_host="other-host"))


def test_execution_chain_rejects_events_outside_window():
    assert not _has_high_chain(_execution_chain(network_delay=6))


def test_execution_chain_rejects_mismatched_executable():
    assert not _has_high_chain(_execution_chain(launch_name="other.exe"))


@pytest.mark.parametrize(
    ("pid", "process_name"),
    [(101, "powershell.exe"), (100, "chrome.exe")],
)
def test_execution_chain_rejects_mismatched_process_identity(pid, process_name):
    assert not _has_high_chain(_execution_chain(network_pid=pid, network_process=process_name))



from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .errors import DeepTraceError


@dataclass(slots=True)
class Event:
    timestamp: datetime
    source: str
    event_type: str
    hostname: str | None = None
    username: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    process_name: str | None = None
    pid: int | None = None
    path: str | None = None
    message: str = ""
    raw_event: Any = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat()
        return value


@dataclass(slots=True)
class Finding:
    name: str
    risk: str
    description: str
    event_indexes: list[int]


SSH = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$")
SSH_AUTH = re.compile(r"(?P<result>Accepted|Failed) \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SYSLOG = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<program>[\w.-]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except ValueError:
            pass
    raise ValueError(f"unsupported timestamp {value!r}")


def normalize_json(record: dict[str, Any]) -> Event:
    timestamp = record.get("timestamp") or record.get("@timestamp") or record.get("UtcTime") or record.get("time")
    try:
        when = parse_timestamp(timestamp)
    except ValueError:
        when = datetime.fromtimestamp(0, timezone.utc)
    event_id = str(record.get("EventID", record.get("event_id", "")))
    event_type = record.get("event_type") or {"1": "process_start", "3": "network_connection", "11": "file_create"}.get(event_id, "unknown")
    image = record.get("Image") or record.get("process_name")
    destination_ip = record.get("DestinationIp") or record.get("destination_ip")
    return Event(
        when, str(record.get("source", "json")), str(event_type), record.get("Computer") or record.get("hostname"),
        record.get("User") or record.get("username"), record.get("SourceIp") or record.get("source_ip"), destination_ip,
        _portable_basename(image) if image else None, _int_or_none(record.get("ProcessId") or record.get("pid")),
        record.get("TargetFilename") or record.get("path"), str(record.get("message", record.get("Message", ""))), record,
    )


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (ValueError, TypeError):
        return None


def normalize_text(line: str, year: int | None = None) -> Event:
    raw = line.rstrip("\n")
    match = SSH.match(raw)
    source = "linux-auth" if match else "syslog"
    match = match or SYSLOG.match(raw)
    if not match:
        return Event(datetime.fromtimestamp(0, timezone.utc), "text", "unknown", message=raw, raw_event=raw)
    values = match.groupdict()
    date_text = f"{year or datetime.now().year} {values['month']} {values['day']} {values['time']}"
    when = datetime.strptime(date_text, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    auth = SSH_AUTH.search(values["msg"]) if source == "linux-auth" else None
    event_type = "ssh_auth_success" if auth and auth["result"] == "Accepted" else "ssh_auth_failure" if auth else "syslog"
    return Event(when, source, event_type, values["host"], auth["user"] if auth else None, auth["ip"] if auth else None, message=values["msg"], raw_event=raw)


def load_events(path: Path) -> list[Event]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DeepTraceError(f"could not read events from {path}: {exc}") from exc
    events: list[Event] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            events.append(normalize_text(line))
            continue
        if isinstance(value, dict):
            events.append(normalize_json(value))
        else:
            events.append(Event(datetime.fromtimestamp(0, timezone.utc), "json", "unknown", message=f"line {number}: non-object JSON", raw_event=value))
    return sorted(events, key=lambda item: item.timestamp)


def correlate(events: Iterable[Event]) -> list[Finding]:
    ordered = list(events)
    findings: list[Finding] = []
    failures: dict[tuple[str | None, str | None], list[int]] = {}
    for index, event in enumerate(ordered):
        if event.event_type == "ssh_auth_failure":
            failures.setdefault((event.source_ip, event.username), []).append(index)
    for (source_ip, username), indexes in failures.items():
        if len(indexes) >= 3:
            findings.append(Finding("Repeated SSH authentication failures", "Medium", f"{len(indexes)} failures for {username or 'unknown user'} from {source_ip or 'unknown source'}", indexes))

    for start, event in enumerate(ordered):
        if event.event_type != "process_start" or (event.process_name or "").lower() not in {"powershell.exe", "pwsh.exe", "powershell"}:
            continue
        related = [(i, candidate) for i, candidate in enumerate(ordered[start + 1 : start + 8], start + 1)]
        network = next(((i, e) for i, e in related if e.event_type == "network_connection" and e.destination_ip), None)
        created = next(((i, e) for i, e in related if e.event_type == "file_create" and e.path and _is_temp_executable(e.path)), None)
        launched = next(((i, e) for i, e in related if e.event_type == "process_start" and created and e.process_name and _portable_basename(created[1].path or "").lower() == e.process_name.lower()), None)
        if network and created and launched:
            findings.append(Finding("Script-to-download execution chain", "High", "PowerShell execution followed by an external connection, a temporary executable, and its launch", [start, network[0], created[0], launched[0]]))

    for index, event in enumerate(ordered):
        if event.event_type == "file_create" and event.path and _is_temp_executable(event.path):
            if not any(index in finding.event_indexes for finding in findings):
                findings.append(Finding("Executable created in temporary directory", "Low", event.path, [index]))
    return findings


def _is_temp_executable(path: str) -> bool:
    value = path.replace("\\", "/").lower()
    return ("/temp/" in value or value.startswith("/tmp/")) and value.endswith((".exe", ".dll", ".sh", ".bin"))


def _portable_basename(path: str) -> str:
    """Treat both slash styles as separators regardless of the host running DeepTrace."""
    return path.replace("\\", "/").rsplit("/", 1)[-1]


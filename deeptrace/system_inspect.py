from __future__ import annotations

import platform
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from .errors import DeepTraceError


def _address(value: Any) -> str:
    if not value:
        return ""
    host = getattr(value, "ip", None) or value[0]
    port = getattr(value, "port", None)
    return f"{host}:{port}" if port else str(host)


def host_report() -> dict[str, Any]:
    interfaces: dict[str, list[str]] = {}
    for name, addresses in psutil.net_if_addrs().items():
        interfaces[name] = [addr.address for addr in addresses if addr.family in (socket.AF_INET, socket.AF_INET6)]
    listeners = []
    listener_note = None
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError, RuntimeError) as exc:
        # Some Windows sandboxes reject GetExtendedTcpTable even for a read-only query.
        connections = []
        listener_note = f"unavailable: {exc}"
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN or (conn.type == socket.SOCK_DGRAM and conn.laddr):
            listeners.append({"protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP", "local": _address(conn.laddr), "pid": conn.pid, "state": conn.status or "NONE"})
    vm = psutil.virtual_memory()
    return {
        "os": platform.platform(), "hostname": socket.gethostname(), "architecture": platform.machine(),
        "python": platform.python_version(), "cpu_count": psutil.cpu_count(),
        "memory": {"total": vm.total, "available": vm.available, "percent_used": vm.percent},
        "interfaces": interfaces, "dns": _dns_servers(), "listening_ports": sorted(listeners, key=lambda item: item["local"])[:100],
        "listening_ports_note": listener_note,
    }


def _dns_servers() -> list[str]:
    if platform.system() == "Linux":
        try:
            return [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines() if line.startswith("nameserver ")]
        except OSError:
            return []
    return ["Use `ipconfig /all` for adapter-specific DNS servers"] if platform.system() == "Windows" else []


def _native_process(pid: int) -> dict[str, Any]:
    if platform.system() != "Linux":
        return {"native_note": "Windows details use psutil backed by documented system APIs"}
    base = Path(f"/proc/{pid}")
    result: dict[str, Any] = {}
    try:
        status = base.joinpath("status").read_text(errors="replace")
        result["proc_status"] = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in status.splitlines() if ":" in line and line.split(":", 1)[0] in {"Name", "State", "Threads", "VmRSS"}}
        result["fd_count"] = sum(1 for _ in base.joinpath("fd").iterdir())
    except (OSError, PermissionError) as exc:
        result["proc_status"] = f"unavailable: {exc}"
    return result


def _process_field(call: Any) -> Any:
    try:
        return call()
    except psutil.AccessDenied:
        return "unavailable: access denied"
    except psutil.NoSuchProcess:
        raise
    except psutil.Error as exc:
        return f"unavailable: {exc}"


def _child_summaries(process: psutil.Process) -> list[dict[str, Any]] | str:
    children = _process_field(lambda: process.children(recursive=False))
    if isinstance(children, str):
        return children
    result = []
    for child in children:
        try:
            name = child.name()
        except psutil.AccessDenied:
            name = "unavailable: access denied"
        except psutil.NoSuchProcess:
            name = "unavailable: process exited"
        except psutil.Error as exc:
            name = f"unavailable: {exc}"
        result.append({"pid": child.pid, "name": name})
    return result


def _process_connections(process: psutil.Process) -> list[Any] | str:
    try:
        return process.net_connections(kind="inet")
    except psutil.AccessDenied:
        return "unavailable: access denied"
    except psutil.NoSuchProcess:
        raise
    except (psutil.Error, OSError, RuntimeError) as exc:
        return f"unavailable: {exc}"


def process_report(pid: int) -> dict[str, Any]:
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            children = _child_summaries(process)
            connections = _process_connections(process)
            if isinstance(connections, str):
                connection_report: list[dict[str, str]] | str = connections
            else:
                connection_report = [{"local": _address(c.laddr), "remote": _address(c.raddr), "state": c.status or "NONE"} for c in connections]
            executable = _process_field(process.exe)
            start_value = _process_field(process.create_time)
            start_time = datetime.fromtimestamp(start_value, timezone.utc).isoformat() if isinstance(start_value, (int, float)) else start_value
            report = {
                "pid": process.pid, "ppid": _process_field(process.ppid), "name": _process_field(process.name),
                "executable": executable or "unavailable", "command_line": _process_field(process.cmdline),
                "username": _process_field(process.username), "start_time": start_time,
                "status": _process_field(process.status), "children": children,
                "connections": connection_report,
                "native": _native_process(pid),
            }
    except psutil.NoSuchProcess as exc:
        raise DeepTraceError(f"process {pid} does not exist") from exc
    except psutil.Error as exc:
        raise DeepTraceError(f"could not inspect process {pid}: {exc}") from exc
    return report

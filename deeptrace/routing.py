from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
from dataclasses import dataclass

from .errors import DeepTraceError


@dataclass(slots=True)
class RouteDecision:
    destination: str
    matched_route: str
    prefix_length: int
    gateway: str
    interface: str
    scope: str
    next_hop: str


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeepTraceError(f"routing table command unavailable: {exc}") from exc
    if result.returncode:
        raise DeepTraceError(result.stderr.strip() or "routing table command failed")
    return result.stdout


def decide(destination: str) -> RouteDecision:
    try:
        address = ipaddress.IPv4Address(destination)
    except ValueError as exc:
        raise DeepTraceError(f"invalid IPv4 destination: {exc}") from exc
    system = platform.system()
    if system == "Windows":
        text = _run(["route", "print", "-4", str(address)])
        candidates: list[tuple[ipaddress.IPv4Network, str, str]] = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            try:
                network = ipaddress.IPv4Network((fields[0], fields[1]), strict=False)
            except ValueError:
                continue
            if address in network:
                candidates.append((network, fields[2], fields[3]))
        if not candidates:
            raise DeepTraceError("no matching IPv4 route was found")
        network, gateway, interface = max(candidates, key=lambda item: item[0].prefixlen)
    elif system == "Linux":
        line = _run(["ip", "-4", "route", "get", str(address)]).splitlines()[0]
        via = re.search(r"\bvia\s+(\S+)", line)
        dev = re.search(r"\bdev\s+(\S+)", line)
        src = re.search(r"\bsrc\s+(\S+)", line)
        gateway = via.group(1) if via else "on-link"
        interface = dev.group(1) if dev else (src.group(1) if src else "unknown")
        network = ipaddress.IPv4Network(f"{address}/32")
    else:
        raise DeepTraceError(f"routing inspection is not implemented on {system}")
    on_link = gateway in ("0.0.0.0", "On-link", "on-link")
    return RouteDecision(str(address), str(network), network.prefixlen, gateway, interface, "local/on-link" if on_link else "remote", str(address) if on_link else gateway)

from __future__ import annotations

import ipaddress
import json
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


def _parse_windows_route_table(text: str, destination: ipaddress.IPv4Address) -> tuple[ipaddress.IPv4Network, str, str]:
    candidates: list[tuple[ipaddress.IPv4Network, int, str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        try:
            network = ipaddress.IPv4Network((fields[0], fields[1]), strict=False)
            interface = str(ipaddress.IPv4Address(fields[-2]))
            metric = int(fields[-1])
        except (ValueError, IndexError):
            continue
        if destination not in network:
            continue
        gateway_text = " ".join(fields[2:-2])
        try:
            gateway = str(ipaddress.IPv4Address(gateway_text))
        except ValueError:
            # Windows localizes the text used for an on-link gateway.
            gateway = "on-link"
        candidates.append((network, metric, gateway, interface))
    if not candidates:
        raise DeepTraceError("no matching IPv4 route was found")
    network, _metric, gateway, interface = max(candidates, key=lambda item: (item[0].prefixlen, -item[1]))
    return network, gateway, interface


def _parse_windows_selected_route(text: str, destination: ipaddress.IPv4Address) -> tuple[ipaddress.IPv4Network, str, str]:
    try:
        value = json.loads(text)
        network = ipaddress.IPv4Network(value["DestinationPrefix"], strict=False)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise DeepTraceError("Windows returned an invalid selected route") from exc
    if destination not in network:
        raise DeepTraceError("Windows selected route does not contain the destination")
    next_hop = str(value.get("NextHop") or "0.0.0.0")
    gateway = "on-link" if next_hop == "0.0.0.0" else next_hop
    interface = str(value.get("InterfaceAlias") or value.get("SourceAddress") or value.get("InterfaceIndex") or "unknown")
    return network, gateway, interface


def _windows_route(destination: ipaddress.IPv4Address) -> tuple[ipaddress.IPv4Network, str, str]:
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$selection=@(Find-NetRoute -RemoteIPAddress '{destination}'); "
        "$route=$selection | Where-Object { $_.DestinationPrefix } | Select-Object -First 1; "
        "$source=$selection | Where-Object { $_.IPAddress } | Select-Object -First 1; "
        "if ($null -eq $route) { throw 'No selected route' }; "
        "[pscustomobject]@{DestinationPrefix=$route.DestinationPrefix;NextHop=$route.NextHop;"
        "InterfaceAlias=if($route.InterfaceAlias){$route.InterfaceAlias}else{$source.InterfaceAlias};"
        "InterfaceIndex=$route.InterfaceIndex;SourceAddress=$source.IPAddress} | ConvertTo-Json -Compress"
    )
    try:
        return _parse_windows_selected_route(_run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]), destination)
    except DeepTraceError:
        # Find-NetRoute can be unavailable in restricted sessions. The full route
        # table is a reliable fallback; filtering route.exe by destination is not.
        return _parse_windows_route_table(_run(["route", "print", "-4"]), destination)


def decide(destination: str) -> RouteDecision:
    try:
        address = ipaddress.IPv4Address(destination)
    except ValueError as exc:
        raise DeepTraceError(f"invalid IPv4 destination: {exc}") from exc
    system = platform.system()
    if system == "Windows":
        network, gateway, interface = _windows_route(address)
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

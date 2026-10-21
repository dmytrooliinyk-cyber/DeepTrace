from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .cidr import calculate
from .dns import TYPES, query
from .errors import DeepTraceError, ParseError
from .events import correlate, load_events
from .explain import explain_ipv4
from .files import inspect_file
from .network import packet_summary
from .output import print_json, print_pairs
from .pcap import PcapReader, handshake_progress, summarize_flows
from .routing import decide
from .system_inspect import host_report, process_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deeptrace", description="Inspect packets, files, processes, networks, and security events below their usual abstractions.")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON where supported")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("host", help="inspect the local host")
    process = sub.add_parser("process", help="inspect one process")
    process.add_argument("pid", type=int)
    file_parser = sub.add_parser("file", help="inspect a file and executable headers")
    file_parser.add_argument("path", type=Path)
    pcap = sub.add_parser("pcap", help="decode a classic PCAP file")
    pcap.add_argument("path", type=Path)
    dns = sub.add_parser("dns", help="build a DNS query and parse the reply")
    dns.add_argument("name")
    dns.add_argument("--server", default="8.8.8.8")
    dns.add_argument("--type", choices=sorted(TYPES.values()), default="A")
    subnet = sub.add_parser("subnet", help="explain an IPv4 CIDR network")
    subnet.add_argument("cidr")
    route = sub.add_parser("route", help="explain the local route to a destination")
    route.add_argument("destination")
    timeline = sub.add_parser("timeline", help="normalize, order, and correlate events")
    timeline.add_argument("path", type=Path)
    explain = sub.add_parser("explain", help="explain header bits from a packet capture")
    explain.add_argument("topic", choices=["ipv4"])
    explain.add_argument("path", type=Path)
    return parser


def _pcap(path: Path, as_json: bool) -> None:
    reader = PcapReader.from_path(path)
    records = list(reader.records())
    flows = summarize_flows(records)
    handshakes = handshake_progress(records)
    if as_json:
        print_json({"header": reader.header, "packets": [{"timestamp": r.timestamp, "captured_length": r.captured_length, "summary": packet_summary(r.frame) if r.frame else None, "error": r.error} for r in records], "flows": [{"flow": key, "packets": count} for key, count in flows.items()], "handshakes": handshakes})
        return
    print(f"PCAP {reader.header.version_major}.{reader.header.version_minor}, link type {reader.header.link_type}, snaplen {reader.header.snaplen}")
    for index, record in enumerate(records, 1):
        stamp = record.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3]
        print(f"{index:>3}  {stamp}  {packet_summary(record.frame) if record.frame else 'decode error: ' + str(record.error)}")
    print("\nFlows")
    for key, count in flows.items():
        print(f"{key.source}:{key.source_port} -> {key.destination}:{key.destination_port} {key.protocol}  packets={count}")
    if handshakes:
        print("\nTCP handshake observations")
        for key, state in handshakes.items():
            print(f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}  {state}")


def _timeline(path: Path, as_json: bool) -> None:
    events = load_events(path)
    findings = correlate(events)
    if as_json:
        print_json({"events": [event.to_dict() for event in events], "findings": findings})
        return
    for index, event in enumerate(events):
        details = event.process_name or event.source_ip or event.path or event.message
        print(f"{index:>3}  {event.timestamp.isoformat()}  {event.event_type:<22} {details}")
    if findings:
        print("\nCorrelated findings")
        for finding in findings:
            print(f"[{finding.risk}] {finding.name}: {finding.description} (events {finding.event_indexes})")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "host":
            print_json(host_report())
        elif args.command == "process":
            print_json(process_report(args.pid))
        elif args.command == "file":
            print_json(inspect_file(args.path))
        elif args.command == "pcap":
            _pcap(args.path, args.json)
        elif args.command == "dns":
            qtype = {name: number for number, name in TYPES.items()}[args.type]
            print_json(query(args.name, args.server, qtype))
        elif args.command == "subnet":
            report = calculate(args.cidr)
            print_json(report) if args.json else print_pairs(report.__dict__ if hasattr(report, "__dict__") else {slot: getattr(report, slot) for slot in report.__slots__})
        elif args.command == "route":
            print_json(decide(args.destination))
        elif args.command == "timeline":
            _timeline(args.path, args.json)
        elif args.command == "explain":
            print(explain_ipv4(args.path))
        return 0
    except (DeepTraceError, ParseError, ValueError) as exc:
        print(f"deeptrace: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("deeptrace: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

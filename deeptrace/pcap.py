from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .binary import require
from .errors import ParseError
from .network import EthernetFrame, IPv4Packet, TCPPacket, UDPPacket, parse_ethernet


@dataclass(slots=True)
class PcapHeader:
    byte_order: str
    nanosecond_resolution: bool
    version_major: int
    version_minor: int
    snaplen: int
    link_type: int


@dataclass(slots=True)
class PcapRecord:
    timestamp: datetime
    captured_length: int
    original_length: int
    data: bytes
    frame: EthernetFrame | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class FlowKey:
    source: str
    source_port: int
    destination: str
    destination_port: int
    protocol: str


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


class PcapReader:
    def __init__(self, data: bytes):
        require(data, 0, 24, "PCAP global header")
        try:
            order, nano = MAGIC[data[:4]]
        except KeyError as exc:
            raise ParseError(f"unrecognized PCAP magic {data[:4].hex()}") from exc
        major, minor, _zone, _sigfigs, snaplen, link_type = struct.unpack_from(f"{order}HHiiii", data, 4)
        if major != 2:
            raise ParseError(f"unsupported PCAP version {major}.{minor}")
        self.data = data
        self.header = PcapHeader(order, nano, major, minor, snaplen, link_type)

    @classmethod
    def from_path(cls, path: Path) -> "PcapReader":
        try:
            return cls(path.read_bytes())
        except OSError as exc:
            raise ParseError(f"could not read {path}: {exc}") from exc

    def records(self) -> Iterator[PcapRecord]:
        offset = 24
        order = self.header.byte_order
        divisor = 1_000_000_000 if self.header.nanosecond_resolution else 1_000_000
        while offset < len(self.data):
            require(self.data, offset, 16, "PCAP packet header")
            seconds, fraction, captured, original = struct.unpack_from(f"{order}IIII", self.data, offset)
            offset += 16
            require(self.data, offset, captured, "PCAP packet data")
            packet_data = self.data[offset : offset + captured]
            offset += captured
            timestamp = datetime.fromtimestamp(seconds + fraction / divisor, tz=timezone.utc)
            record = PcapRecord(timestamp, captured, original, packet_data)
            if self.header.link_type != 1:
                record.error = f"unsupported link type {self.header.link_type}; only Ethernet is decoded"
            else:
                try:
                    record.frame = parse_ethernet(packet_data)
                except ParseError as exc:
                    record.error = str(exc)
            yield record


def flow_key(frame: EthernetFrame) -> FlowKey | None:
    if not isinstance(frame.protocol, IPv4Packet):
        return None
    ip = frame.protocol
    transport = ip.transport
    if isinstance(transport, TCPPacket):
        return FlowKey(ip.source, transport.source_port, ip.destination, transport.destination_port, "TCP")
    if isinstance(transport, UDPPacket):
        return FlowKey(ip.source, transport.source_port, ip.destination, transport.destination_port, "UDP")
    return None


def summarize_flows(records: list[PcapRecord]) -> Counter[FlowKey]:
    flows: Counter[FlowKey] = Counter()
    for record in records:
        key = flow_key(record.frame) if record.frame else None
        if key:
            flows[key] += 1
    return flows


def handshake_progress(records: list[PcapRecord]) -> dict[tuple[str, int, str, int], str]:
    states: dict[tuple[str, int, str, int], str] = {}
    for record in records:
        if not record.frame or not isinstance(record.frame.protocol, IPv4Packet):
            continue
        ip = record.frame.protocol
        tcp = ip.transport
        if not isinstance(tcp, TCPPacket):
            continue
        forward = (ip.source, tcp.source_port, ip.destination, tcp.destination_port)
        reverse = (ip.destination, tcp.destination_port, ip.source, tcp.source_port)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            states[forward] = "SYN seen"
        elif tcp.flags & 0x12 == 0x12 and states.get(reverse) == "SYN seen":
            states[reverse] = "SYN/ACK seen"
        elif tcp.flags & 0x10 and states.get(forward) == "SYN/ACK seen":
            states[forward] = "handshake observed"
    return states


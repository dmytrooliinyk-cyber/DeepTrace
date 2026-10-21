from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

from .binary import require, unpack_from
from .errors import ParseError


def mac(value: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in value)


@dataclass(slots=True)
class EthernetFrame:
    destination: str
    source: str
    ethertype: int
    payload: bytes = field(repr=False)
    protocol: Any | None = None


@dataclass(slots=True)
class IPv4Packet:
    version: int
    ihl: int
    header_length: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol_number: int
    checksum: int
    source: str
    destination: str
    payload: bytes = field(repr=False)
    transport: Any | None = None


@dataclass(slots=True)
class TCPPacket:
    source_port: int
    destination_port: int
    sequence: int
    acknowledgment: int
    header_length: int
    flags: int
    window: int
    checksum: int
    payload: bytes = field(repr=False)

    @property
    def flag_names(self) -> list[str]:
        names = [(0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]
        return [name for mask, name in names if self.flags & mask]


@dataclass(slots=True)
class UDPPacket:
    source_port: int
    destination_port: int
    length: int
    checksum: int
    payload: bytes = field(repr=False)


@dataclass(slots=True)
class ICMPPacket:
    type: int
    code: int
    checksum: int
    description: str
    identifier: int | None = None
    sequence: int | None = None


@dataclass(slots=True)
class ARPPacket:
    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


def parse_ethernet(data: bytes) -> EthernetFrame:
    require(data, 0, 14, "Ethernet header")
    destination, source, ethertype = unpack_from("!6s6sH", data, label="Ethernet header")
    frame = EthernetFrame(mac(destination), mac(source), ethertype, data[14:])
    if ethertype == 0x0800:
        frame.protocol = parse_ipv4(frame.payload)
    elif ethertype == 0x0806:
        frame.protocol = parse_arp(frame.payload)
    return frame


def parse_ipv4(data: bytes) -> IPv4Packet:
    require(data, 0, 20, "IPv4 header")
    first = data[0]
    version, ihl = first >> 4, first & 0x0F
    header_length = ihl * 4
    if version != 4:
        raise ParseError(f"unsupported IP version {version}")
    if ihl < 5:
        raise ParseError(f"invalid IPv4 IHL {ihl}")
    require(data, 0, header_length, "IPv4 header with options")
    total_length = struct.unpack_from("!H", data, 2)[0]
    if total_length < header_length:
        raise ParseError("IPv4 total length is shorter than its header")
    available_end = min(total_length, len(data))
    identification, flag_fragment = struct.unpack_from("!HH", data, 4)
    ttl, protocol_number, checksum = struct.unpack_from("!BBH", data, 8)
    packet = IPv4Packet(
        version, ihl, header_length, total_length, identification,
        flag_fragment >> 13, flag_fragment & 0x1FFF, ttl, protocol_number, checksum,
        str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20])),
        data[header_length:available_end],
    )
    if packet.fragment_offset == 0:
        parsers = {1: parse_icmp, 6: parse_tcp, 17: parse_udp}
        parser = parsers.get(protocol_number)
        if parser:
            packet.transport = parser(packet.payload)
    return packet


def parse_tcp(data: bytes) -> TCPPacket:
    require(data, 0, 20, "TCP header")
    src, dst, seq, ack, offset_flags, window, checksum, _urgent = unpack_from("!HHIIHHHH", data, label="TCP header")
    header_length = ((offset_flags >> 12) & 0xF) * 4
    if header_length < 20:
        raise ParseError(f"invalid TCP header length {header_length}")
    require(data, 0, header_length, "TCP header with options")
    return TCPPacket(src, dst, seq, ack, header_length, offset_flags & 0x1FF, window, checksum, data[header_length:])


def parse_udp(data: bytes) -> UDPPacket:
    src, dst, length, checksum = unpack_from("!HHHH", data, label="UDP header")
    if length < 8:
        raise ParseError(f"invalid UDP length {length}")
    return UDPPacket(src, dst, length, checksum, data[8 : min(length, len(data))])


def parse_icmp(data: bytes) -> ICMPPacket:
    type_, code, checksum = unpack_from("!BBH", data, label="ICMP header")
    descriptions = {(0, 0): "echo reply", (8, 0): "echo request", (3, 0): "destination unreachable", (11, 0): "time exceeded"}
    identifier = sequence = None
    if type_ in (0, 8) and len(data) >= 8:
        identifier, sequence = struct.unpack_from("!HH", data, 4)
    return ICMPPacket(type_, code, checksum, descriptions.get((type_, code), "other ICMP message"), identifier, sequence)


def parse_arp(data: bytes) -> ARPPacket:
    require(data, 0, 28, "Ethernet/IPv4 ARP packet")
    hardware, protocol, hlen, plen, operation = unpack_from("!HHBBH", data, label="ARP header")
    if (hardware, protocol, hlen, plen) != (1, 0x0800, 6, 4):
        raise ParseError("only Ethernet/IPv4 ARP packets are supported")
    return ARPPacket(operation, mac(data[8:14]), str(ipaddress.ip_address(data[14:18])), mac(data[18:24]), str(ipaddress.ip_address(data[24:28])))


def packet_summary(frame: EthernetFrame) -> str:
    layer = frame.protocol
    if isinstance(layer, ARPPacket):
        op = "request" if layer.operation == 1 else "reply" if layer.operation == 2 else str(layer.operation)
        return f"ARP {op} {layer.sender_ip} -> {layer.target_ip}"
    if not isinstance(layer, IPv4Packet):
        return f"EtherType 0x{frame.ethertype:04x}"
    transport = layer.transport
    if isinstance(transport, TCPPacket):
        flags = "/".join(transport.flag_names) or "no flags"
        return f"{layer.source}:{transport.source_port} -> {layer.destination}:{transport.destination_port} TCP {flags}"
    if isinstance(transport, UDPPacket):
        return f"{layer.source}:{transport.source_port} -> {layer.destination}:{transport.destination_port} UDP"
    if isinstance(transport, ICMPPacket):
        return f"{layer.source} -> {layer.destination} ICMP {transport.description}"
    return f"{layer.source} -> {layer.destination} IPv4 protocol {layer.protocol_number}"

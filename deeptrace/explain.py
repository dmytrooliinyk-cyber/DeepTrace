from __future__ import annotations

from pathlib import Path

from .errors import DeepTraceError
from .network import IPv4Packet, TCPPacket
from .pcap import PcapReader


def explain_ipv4(path: Path) -> str:
    reader = PcapReader.from_path(path)
    for record in reader.records():
        if record.frame and isinstance(record.frame.protocol, IPv4Packet):
            ip = record.frame.protocol
            first = record.frame.payload[0]
            lines = [
                f"First byte: 0x{first:02x}", f"Binary: {first:08b}",
                f"Version: {first >> 4:04b} = {ip.version}", f"IHL: {first & 0x0f:04b} = {ip.ihl}",
                f"Header length: {ip.ihl} x 4 = {ip.header_length} bytes",
                f"Flags: {ip.flags:03b}; fragment offset: {ip.fragment_offset}",
                f"TTL: {ip.ttl}; protocol number: {ip.protocol_number}",
            ]
            if isinstance(ip.transport, TCPPacket):
                tcp = ip.transport
                lines.extend(["", f"TCP flags: 0x{tcp.flags:02x}", f"Binary: {tcp.flags:08b}"])
                for mask, name in ((0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"), (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")):
                    lines.append(f"{name} = {1 if tcp.flags & mask else 0}")
                lines.append(f"Meaning: {'/'.join(tcp.flag_names) or 'no control flags'}")
            return "\n".join(lines)
    raise DeepTraceError("no decodable IPv4 packet was found in the capture")


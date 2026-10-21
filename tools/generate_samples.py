"""Generate deterministic, safe sample inputs used in the repository."""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "sample-data"


def tcp_packet(source: bytes, destination: bytes, source_port: int, destination_port: int, flags: int, sequence: int, acknowledgment: int) -> bytes:
    tcp = struct.pack("!HHIIHHHH", source_port, destination_port, sequence, acknowledgment, (5 << 12) | flags, 64240, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, sequence & 0xFFFF, 0x4000, 64, 6, 0, source, destination) + tcp
    return bytes.fromhex("001122334455aabbccddeeff0800") + ip


def make_pcap() -> bytes:
    client, server = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20])
    packets = [
        tcp_packet(client, server, 51532, 443, 0x02, 100, 0),
        tcp_packet(server, client, 443, 51532, 0x12, 900, 101),
        tcp_packet(client, server, 51532, 443, 0x10, 101, 901),
    ]
    output = bytearray(bytes.fromhex("d4c3b2a1") + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        output.extend(struct.pack("<IIII", 1760954400 + index, 120000 + index * 1000, len(packet), len(packet)))
        output.extend(packet)
    return bytes(output)


def main() -> None:
    SAMPLES.mkdir(exist_ok=True)
    (SAMPLES / "sample.pcap").write_bytes(make_pcap())
    events = [
        {"timestamp": "2026-10-20T10:00:00Z", "source": "sysmon", "event_type": "process_start", "hostname": "lab-host", "process_name": "powershell.exe", "pid": 4100, "message": "PowerShell started"},
        {"timestamp": "2026-10-20T10:00:02Z", "source": "sysmon", "event_type": "network_connection", "hostname": "lab-host", "process_name": "powershell.exe", "pid": 4100, "destination_ip": "198.51.100.20"},
        {"timestamp": "2026-10-20T10:00:04Z", "source": "sysmon", "event_type": "file_create", "hostname": "lab-host", "path": "C:\\Users\\demo\\AppData\\Local\\Temp\\stage.exe"},
        {"timestamp": "2026-10-20T10:00:06Z", "source": "sysmon", "event_type": "process_start", "hostname": "lab-host", "process_name": "stage.exe", "pid": 4200},
    ]
    (SAMPLES / "events.jsonl").write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
    (SAMPLES / "linux-auth.log").write_text("Oct 20 11:00:00 lab-host sshd[100]: Failed password for invalid user admin from 192.0.2.50 port 50001 ssh2\nOct 20 11:00:02 lab-host sshd[101]: Failed password for invalid user admin from 192.0.2.50 port 50002 ssh2\nOct 20 11:00:04 lab-host sshd[102]: Failed password for invalid user admin from 192.0.2.50 port 50003 ssh2\n", encoding="utf-8")
    (SAMPLES / "malformed-packet.bin").write_bytes(b"\x45\x00\x00")


if __name__ == "__main__":
    main()

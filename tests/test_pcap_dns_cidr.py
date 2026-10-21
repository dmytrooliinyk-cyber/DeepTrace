import struct

import pytest

from deeptrace.cidr import calculate
from deeptrace.dns import build_query, decode_name, parse_message
from deeptrace.errors import ParseError
from deeptrace.pcap import PcapReader, summarize_flows


def ethernet_tcp() -> bytes:
    tcp = struct.pack("!HHIIHHHH", 50000, 443, 1, 0, (5 << 12) | 2, 1024, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x4000, 64, 6, 0, b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02") + tcp
    return bytes.fromhex("001122334455aabbccddeeff0800") + ip


def pcap_bytes(packet: bytes) -> bytes:
    return bytes.fromhex("d4c3b2a1") + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1700000000, 123000, len(packet), len(packet)) + packet


def test_pcap_header_record_and_flow():
    reader = PcapReader(pcap_bytes(ethernet_tcp()))
    records = list(reader.records())
    assert reader.header.byte_order == "<"
    assert reader.header.snaplen == 65535
    assert records[0].frame is not None
    flows = summarize_flows(records)
    key = next(iter(flows))
    assert key.protocol == "TCP"
    assert flows[key] == 1


def test_bad_pcap_magic_and_truncated_record():
    with pytest.raises(ParseError):
        PcapReader(b"bad" + b"\0" * 30)
    reader = PcapReader(bytes.fromhex("d4c3b2a1") + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1) + b"\0")
    with pytest.raises(ParseError):
        list(reader.records())


def test_dns_plain_and_compressed_name():
    name = b"\x07example\x03com\x00"
    packet = struct.pack("!HHHHHH", 0xBEEF, 0x8180, 1, 1, 0, 0) + name + struct.pack("!HH", 1, 1)
    packet += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\xc0\x00\x02\x2a"
    message = parse_message(packet)
    assert message.questions[0].name == "example.com"
    assert message.answers[0].name == "example.com"
    assert message.answers[0].value == "192.0.2.42"
    assert decode_name(packet, len(packet) - 16)[0] == "example.com"


def test_dns_query_bytes_and_pointer_loop():
    transaction_id, query = build_query("example.com", transaction_id=123)
    assert transaction_id == 123
    assert query.startswith(b"\x00{\x01\x00")
    with pytest.raises(ParseError):
        decode_name(b"\xc0\x00", 0)


def test_cidr_math():
    report = calculate("192.168.10.73/27")
    assert report.network == "192.168.10.64"
    assert report.broadcast == "192.168.10.95"
    assert report.first_usable == "192.168.10.65"
    assert report.last_usable == "192.168.10.94"
    assert report.usable_hosts == 30
    assert report.mask_binary == "11111111.11111111.11111111.11100000"


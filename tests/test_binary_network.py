import struct

import pytest

from deeptrace.binary import bits, shannon_entropy, u16be, u16le
from deeptrace.errors import ParseError
from deeptrace.network import ARPPacket, IPv4Packet, TCPPacket, UDPPacket, parse_arp, parse_ethernet, parse_ipv4, parse_tcp, parse_udp


def ipv4(payload: bytes, protocol: int = 6, flags_fragment: int = 0x4000) -> bytes:
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, flags_fragment, 64, protocol, 0, b"\xc0\x00\x02\x0a", b"\xc6\x33\x64\x14") + payload


def test_endian_bits_and_entropy():
    assert u16be(b"\x12\x34") == 0x1234
    assert u16le(b"\x12\x34") == 0x3412
    assert bits(0b110101, 1, 3) == 0b010
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"A" * 100) == 0
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_ethernet_ipv4_tcp_flags():
    tcp = struct.pack("!HHIIHHHH", 51532, 443, 100, 0, (5 << 12) | 0x02, 64240, 0, 0)
    packet = ipv4(tcp)
    frame = parse_ethernet(b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff\x08\x00" + packet)
    assert frame.destination == "00:11:22:33:44:55"
    assert isinstance(frame.protocol, IPv4Packet)
    assert frame.protocol.header_length == 20
    assert frame.protocol.source == "192.0.2.10"
    assert frame.protocol.flags == 2
    assert isinstance(frame.protocol.transport, TCPPacket)
    assert frame.protocol.transport.flag_names == ["SYN"]


def test_udp_and_arp():
    udp = parse_udp(struct.pack("!HHHH", 53000, 53, 11, 0) + b"abc")
    assert isinstance(udp, UDPPacket)
    assert udp.payload == b"abc"
    arp_bytes = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("aabbccddeeffc000020a000000000000c0000201")
    arp = parse_arp(arp_bytes)
    assert isinstance(arp, ARPPacket)
    assert arp.sender_ip == "192.0.2.10"
    assert arp.target_ip == "192.0.2.1"


@pytest.mark.parametrize("parser,data", [(parse_ethernet, b"short"), (parse_ipv4, b"\x45"), (parse_tcp, b"\0" * 10), (parse_udp, b"\0" * 4)])
def test_truncated_packets_raise_parse_error(parser, data):
    with pytest.raises(ParseError):
        parser(data)


def test_non_initial_fragment_does_not_parse_transport():
    packet = parse_ipv4(ipv4(b"not a tcp header", flags_fragment=1))
    assert packet.fragment_offset == 1
    assert packet.transport is None


import struct

import pytest

from deeptrace.errors import ParseError
from deeptrace.executables import parse_elf, parse_pe
from deeptrace.files import detect_type


def minimal_pe() -> bytes:
    data = bytearray(0x220)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 1700000000, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 16, 0x1000)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    section = 0x98 + 0xF0
    struct.pack_into("<8sIIIIIIHHI", data, section, b".text\0\0\0", 0x100, 0x1000, 0x20, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x220] = bytes(range(32))
    return bytes(data)


def minimal_elf64() -> bytes:
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    return ident + header


@pytest.mark.parametrize("data,expected", [(b"MZx", "PE"), (b"\x7fELF", "ELF"), (b"%PDF-1.7", "PDF"), (b"PK\x03\x04x", "ZIP"), (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\xff\xd8\xff", "JPEG"), (b"plain", "unknown")])
def test_magic_detection(data, expected):
    assert detect_type(data) == expected


def test_pe_parsing():
    pe = parse_pe(minimal_pe())
    assert pe.machine == "x86-64"
    assert pe.entry_point == 0x1000
    assert pe.image_base == 0x140000000
    assert pe.sections[0].name == ".text"
    assert pe.sections[0].characteristics == "R-X"
    assert pe.sections[0].raw_size == 0x20


def test_elf_parsing():
    elf = parse_elf(minimal_elf64())
    assert elf.bit_class == "64-bit"
    assert elf.endianness == "little"
    assert elf.machine == "x86-64"
    assert elf.entry_point == 0x401000
    assert elf.program_header_count == 2


def test_truncated_executables():
    with pytest.raises(ParseError):
        parse_pe(b"MZ")
    with pytest.raises(ParseError):
        parse_elf(b"\x7fELF")


def _pe_with_section_range(raw_offset, raw_size):
    data = bytearray(minimal_pe())
    section = 0x98 + 0xF0
    struct.pack_into("<I", data, section + 16, raw_size)
    struct.pack_into("<I", data, section + 20, raw_offset)
    return bytes(data)


def test_pe_rejects_section_raw_offset_outside_file():
    with pytest.raises(ParseError, match="PE section data 0"):
        parse_pe(_pe_with_section_range(0x1000, 0x20))


def test_pe_rejects_section_extending_beyond_eof():
    with pytest.raises(ParseError, match="PE section data 0"):
        parse_pe(_pe_with_section_range(0x210, 0x20))


def test_pe_allows_zero_length_section_without_reading_raw_offset():
    pe = parse_pe(_pe_with_section_range(0xFFFFFFFF, 0))
    assert pe.sections[0].raw_size == 0
    assert pe.sections[0].entropy == 0.0


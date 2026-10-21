from __future__ import annotations

import string
import struct
from dataclasses import dataclass

from .binary import require, shannon_entropy
from .errors import ParseError


PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64"}
ELF_MACHINES = {3: "x86", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}


@dataclass(slots=True)
class PESection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: str
    entropy: float
    indicators: list[str]


@dataclass(slots=True)
class PEInfo:
    mz_signature: str
    e_lfanew: int
    pe_signature: str
    machine: str
    number_of_sections: int
    timestamp: int
    optional_header_magic: str
    entry_point: int
    image_base: int
    sections: list[PESection]


def _permissions(value: int) -> str:
    return "".join(letter if value & mask else "-" for mask, letter in ((0x40000000, "R"), (0x80000000, "W"), (0x20000000, "X")))


def parse_pe(data: bytes) -> PEInfo:
    require(data, 0, 64, "DOS header")
    if data[:2] != b"MZ":
        raise ParseError("missing MZ signature")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    require(data, e_lfanew, 24, "PE signature and COFF header")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise ParseError("missing PE signature at e_lfanew")
    machine, section_count, timestamp, _symbols, _symbol_count, optional_size, _characteristics = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    optional = e_lfanew + 24
    require(data, optional, optional_size, "PE optional header")
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        require(data, optional, 32, "PE32 optional header")
        entry_point = struct.unpack_from("<I", data, optional + 16)[0]
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
        magic_name = "PE32"
    elif magic == 0x20B:
        require(data, optional, 32, "PE32+ optional header")
        entry_point = struct.unpack_from("<I", data, optional + 16)[0]
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
        magic_name = "PE32+"
    else:
        raise ParseError(f"unsupported PE optional-header magic 0x{magic:04x}")
    table = optional + optional_size
    sections: list[PESection] = []
    for index in range(section_count):
        offset = table + index * 40
        require(data, offset, 40, f"PE section header {index}")
        raw_name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<8sIIII", data, offset)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
        raw = data[raw_offset : raw_offset + raw_size] if raw_offset < len(data) else b""
        entropy = shannon_entropy(raw)
        indicators: list[str] = []
        permissions = _permissions(characteristics)
        if "W" in permissions and "X" in permissions:
            indicators.append("writable and executable (indicator only)")
        if raw and entropy > 7.2:
            indicators.append("high section entropy (indicator only)")
        if name and any(ch not in string.ascii_letters + string.digits + "._$" for ch in name):
            indicators.append("unusual section name (indicator only)")
        sections.append(PESection(name or "(unnamed)", virtual_size, virtual_address, raw_size, raw_offset, permissions, round(entropy, 4), indicators))
    return PEInfo("MZ", e_lfanew, "PE\\0\\0", PE_MACHINES.get(machine, f"0x{machine:04x}"), section_count, timestamp, magic_name, entry_point, image_base, sections)


@dataclass(slots=True)
class ELFInfo:
    magic: str
    bit_class: str
    endianness: str
    os_abi: int
    file_type: int
    machine: str
    entry_point: int
    program_header_offset: int
    section_header_offset: int
    header_size: int
    program_header_count: int
    section_count: int


def parse_elf(data: bytes) -> ELFInfo:
    require(data, 0, 16, "ELF identification")
    if data[:4] != b"\x7fELF":
        raise ParseError("missing ELF magic")
    class_, encoding, os_abi = data[4], data[5], data[7]
    if class_ not in (1, 2) or encoding not in (1, 2):
        raise ParseError("unsupported ELF class or byte order")
    order = "<" if encoding == 1 else ">"
    if class_ == 1:
        fmt, expected = f"{order}HHIIIIIHHHHHH", 52
        fields = struct.unpack_from(fmt, data, 16) if len(data) >= expected else None
    else:
        fmt, expected = f"{order}HHIQQQIHHHHHH", 64
        fields = struct.unpack_from(fmt, data, 16) if len(data) >= expected else None
    if fields is None:
        raise ParseError(f"truncated ELF{32 if class_ == 1 else 64} header")
    file_type, machine, _version, entry, phoff, shoff, _flags, ehsize, _phentsize, phnum, _shentsize, shnum, _shstr = fields
    return ELFInfo("7f 45 4c 46", "32-bit" if class_ == 1 else "64-bit", "little" if encoding == 1 else "big", os_abi, file_type, ELF_MACHINES.get(machine, str(machine)), entry, phoff, shoff, ehsize, phnum, shnum)


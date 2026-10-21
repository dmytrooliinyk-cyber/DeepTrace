from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from .errors import ParseError


def require(data: bytes, offset: int, size: int, label: str = "field") -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        available = max(0, len(data) - offset)
        raise ParseError(f"truncated {label}: need {size} bytes at offset {offset}, have {available}")


def read_uint(data: bytes, offset: int, size: int, byteorder: str = "big") -> int:
    require(data, offset, size, "integer")
    return int.from_bytes(data[offset : offset + size], byteorder)


def u16be(data: bytes, offset: int = 0) -> int:
    return read_uint(data, offset, 2, "big")


def u16le(data: bytes, offset: int = 0) -> int:
    return read_uint(data, offset, 2, "little")


def u32be(data: bytes, offset: int = 0) -> int:
    return read_uint(data, offset, 4, "big")


def u32le(data: bytes, offset: int = 0) -> int:
    return read_uint(data, offset, 4, "little")


def bits(value: int, start: int, width: int) -> int:
    """Extract *width* bits, numbering bit zero from the least significant bit."""
    if start < 0 or width < 0:
        raise ValueError("bit positions must be non-negative")
    return (value >> start) & ((1 << width) - 1)


def hex_bytes(data: bytes, separator: str = " ") -> str:
    return separator.join(f"{byte:02x}" for byte in data)


def unpack_from(fmt: str, data: bytes, offset: int = 0, label: str = "structure") -> tuple:
    size = struct.calcsize(fmt)
    require(data, offset, size, label)
    return struct.unpack_from(fmt, data, offset)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts if n)


@dataclass(slots=True)
class Cursor:
    data: bytes
    offset: int = 0
    byteorder: str = "big"

    def take(self, size: int, label: str = "field") -> bytes:
        require(self.data, self.offset, size, label)
        chunk = self.data[self.offset : self.offset + size]
        self.offset += size
        return chunk

    def uint(self, size: int, label: str = "integer") -> int:
        return int.from_bytes(self.take(size, label), self.byteorder)


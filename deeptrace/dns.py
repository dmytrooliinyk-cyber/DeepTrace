from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass

from .binary import require
from .errors import DeepTraceError, ParseError


TYPES = {1: "A", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}


@dataclass(slots=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


@dataclass(slots=True)
class DNSAnswer:
    name: str
    type: int
    cls: int
    ttl: int
    value: str


@dataclass(slots=True)
class DNSMessage:
    transaction_id: int
    flags: int
    question_count: int
    answer_count: int
    authority_count: int
    additional_count: int
    questions: list[DNSQuestion]
    answers: list[DNSAnswer]


def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    out = bytearray()
    for label in labels:
        encoded = label.encode("idna")
        if not encoded or len(encoded) > 63:
            raise DeepTraceError(f"invalid DNS label {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int, *, _seen: set[int] | None = None) -> tuple[str, int]:
    """Decode labels and RFC 1035 compression pointers without pointer loops."""
    labels: list[str] = []
    consumed = 0
    jumped = False
    seen = set() if _seen is None else _seen
    while True:
        require(data, offset, 1, "DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            require(data, offset, 2, "DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= len(data) or pointer in seen:
                raise ParseError("invalid or cyclic DNS compression pointer")
            seen.add(pointer)
            suffix, _ = decode_name(data, pointer, _seen=seen)
            labels.extend(suffix.split(".") if suffix else [])
            consumed += 2
            jumped = True
            break
        if length & 0xC0:
            raise ParseError("unsupported DNS label encoding")
        offset += 1
        if not jumped:
            consumed += 1
        if length == 0:
            break
        if length > 63:
            raise ParseError("DNS label exceeds 63 bytes")
        require(data, offset, length, "DNS label")
        try:
            labels.append(data[offset : offset + length].decode("ascii"))
        except UnicodeDecodeError as exc:
            raise ParseError("DNS label is not ASCII") from exc
        offset += length
        if not jumped:
            consumed += length
    return ".".join(labels), consumed


def build_query(name: str, qtype: int = 1, transaction_id: int | None = None) -> tuple[int, bytes]:
    transaction_id = random.SystemRandom().randrange(65536) if transaction_id is None else transaction_id
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    return transaction_id, header + encode_name(name) + struct.pack("!HH", qtype, 1)


def _answer_value(data: bytes, rdata_offset: int, rdata: bytes, type_: int) -> str:
    if type_ == 1 and len(rdata) == 4:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if type_ == 28 and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if type_ == 5:
        return decode_name(data, rdata_offset)[0]
    if type_ == 15 and len(rdata) >= 3:
        return f"{struct.unpack_from('!H', rdata)[0]} {decode_name(data, rdata_offset + 2)[0]}"
    if type_ == 16:
        parts, pos = [], 0
        while pos < len(rdata):
            length = rdata[pos]
            pos += 1
            parts.append(rdata[pos : pos + length].decode("utf-8", "replace"))
            pos += length
        return " ".join(parts)
    return rdata.hex()


def parse_message(data: bytes) -> DNSMessage:
    require(data, 0, 12, "DNS header")
    transaction_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data)
    offset, questions, answers = 12, [], []
    for _ in range(qd):
        name, used = decode_name(data, offset)
        offset += used
        require(data, offset, 4, "DNS question fields")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        questions.append(DNSQuestion(name, qtype, qclass))
    for _ in range(an):
        name, used = decode_name(data, offset)
        offset += used
        require(data, offset, 10, "DNS resource record")
        type_, cls, ttl, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        require(data, offset, length, "DNS resource data")
        rdata = data[offset : offset + length]
        answers.append(DNSAnswer(name, type_, cls, ttl, _answer_value(data, offset, rdata, type_)))
        offset += length
    return DNSMessage(transaction_id, flags, qd, an, ns, ar, questions, answers)


def query(name: str, server: str = "8.8.8.8", qtype: int = 1, timeout: float = 3.0) -> DNSMessage:
    transaction_id, payload = build_query(name, qtype)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (server, 53))
            response, _ = sock.recvfrom(65535)
    except (OSError, TimeoutError) as exc:
        raise DeepTraceError(f"DNS query to {server} failed: {exc}") from exc
    message = parse_message(response)
    if message.transaction_id != transaction_id:
        raise ParseError("DNS response transaction ID did not match the query")
    return message


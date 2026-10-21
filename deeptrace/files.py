from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .binary import hex_bytes, shannon_entropy
from .errors import DeepTraceError, ParseError
from .executables import parse_elf, parse_pe


SIGNATURES = [
    (b"MZ", "PE"),
    (b"\x7fELF", "ELF"),
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
]


def detect_type(data: bytes) -> str:
    for signature, name in SIGNATURES:
        if data.startswith(signature):
            return name
    return "unknown"


@dataclass(slots=True)
class FileReport:
    path: str
    size: int
    extension: str
    detected_type: str
    sha256: str
    md5_identification_only: str
    entropy: float
    magic_bytes: str
    created: str
    modified: str
    executable: Any | None = None


def inspect_file(path: Path) -> FileReport:
    try:
        data = path.read_bytes()
        stat = path.stat()
    except OSError as exc:
        raise DeepTraceError(f"could not inspect {path}: {exc}") from exc
    detected = detect_type(data)
    detail = None
    try:
        if detected == "PE":
            detail = parse_pe(data)
        elif detected == "ELF":
            detail = parse_elf(data)
    except ParseError as exc:
        detail = {"parse_error": str(exc)}
    utc = timezone.utc
    return FileReport(
        str(path.resolve()), len(data), path.suffix or "(none)", detected,
        hashlib.sha256(data).hexdigest(), hashlib.md5(data, usedforsecurity=False).hexdigest(),
        round(shannon_entropy(data), 4), hex_bytes(data[:16]),
        datetime.fromtimestamp(stat.st_ctime, utc).isoformat(), datetime.fromtimestamp(stat.st_mtime, utc).isoformat(), detail,
    )


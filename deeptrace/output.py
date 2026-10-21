from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


def serializable(value: Any) -> Any:
    if is_dataclass(value):
        return {k: serializable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serializable(v) for v in value]
    if isinstance(value, (datetime, Path)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    if isinstance(value, Enum):
        return value.value
    return value


def print_json(value: Any) -> None:
    print(json.dumps(serializable(value), indent=2, ensure_ascii=False))


def print_pairs(items: dict[str, Any]) -> None:
    width = max((len(str(key)) for key in items), default=0)
    for key, value in items.items():
        print(f"{key:<{width}}  {value}")


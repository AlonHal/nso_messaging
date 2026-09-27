"""Atomic JSON persistence shared by client and server state stores."""

import json
from pathlib import Path
from typing import Any


def write_json_atomic(path: str | Path, value: Any, *, indent: int | None = None) -> None:
    """Serialize JSON to a sibling temporary file, then atomically replace the destination."""
    destination = Path(path)
    temporary_path = destination.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(value, indent=indent, sort_keys=True))
    temporary_path.replace(destination)

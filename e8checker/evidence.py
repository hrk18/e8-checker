"""Loading and safe access to the evidence JSON produced by the PowerShell collector."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

SUPPORTED_SCHEMAS = (1, 2)  # 2 adds the "ml2" section (collector 0.2.0); 1 is still read


class EvidenceError(ValueError):
    """Raised when an evidence file cannot be used."""


class Evidence:
    """Read-only wrapper around the collector output.

    Every lookup goes through :meth:`get` so a missing section never crashes a check;
    the check reports ERROR instead.
    """

    def __init__(self, data: dict[str, Any]):
        if not isinstance(data, dict):
            raise EvidenceError("Evidence must be a JSON object")
        schema = data.get("schema_version")
        if schema not in SUPPORTED_SCHEMAS:
            expected = " or ".join(str(v) for v in SUPPORTED_SCHEMAS)
            raise EvidenceError(f"Unsupported schema_version {schema!r}; expected {expected}")
        self._data = data

    @classmethod
    def from_file(cls, path: str | Path) -> Evidence:
        path = Path(path)
        try:
            # utf-8-sig: Windows PowerShell 5.1 writes a BOM by default
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise EvidenceError(f"Cannot read evidence file {path}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"{path} is not valid JSON: {exc}") from exc
        return cls(data)

    def get(self, dotted: str, default: Any = None) -> Any:
        """Fetch a nested value, e.g. ``get("os.caption")``."""
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def hostname(self) -> str:
        return str(self.get("host.hostname", "unknown-host"))

    @property
    def collected_at(self) -> datetime | None:
        return parse_date(self.get("collected_at"))

    @property
    def schema_version(self) -> int:
        return int(self._data["schema_version"])

    @property
    def raw(self) -> dict[str, Any]:
        return self._data


def parse_date(value: Any) -> datetime | None:
    """Parse ISO-8601 dates/datetimes from the collector; return None if unusable."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text[:10])
        except ValueError:
            return None
    return parsed.replace(tzinfo=None)

"""Explicit JSON-safe serialization for NetGuard read models."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any


def serialize(value: Any) -> Any:
    """Convert supported read models without exposing arbitrary objects."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return serialize(value.value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: serialize(getattr(value, field.name))
            for field in fields(value)
            if field.name != "payload"
        }
    if isinstance(value, dict):
        return {
            str(key): serialize(item)
            for key, item in value.items()
            if str(key) != "payload"
        }
    if isinstance(value, (list, tuple, set)):
        return [serialize(item) for item in value]
    raise TypeError(
        f"Unsupported API response type: {value.__class__.__name__}"
    )

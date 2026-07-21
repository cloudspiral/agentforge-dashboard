from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

SENSITIVE_KEY = re.compile(r"(authorization|cookie|password|secret|token|api[_-]?key)", re.I)
BEARER_VALUE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")


def redact(value: Any) -> Any:
    """Return a telemetry-safe copy while preserving useful evidence shape."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return BEARER_VALUE.sub("Bearer [REDACTED]", value)
    return value

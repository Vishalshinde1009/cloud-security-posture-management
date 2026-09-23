"""
JSON-Safe Normalization Utility
===============================
Recursively normalizes Python objects (notably AWS SDK / boto3 response objects
such as datetime, date, Decimal, set, etc.) into JSON-serializable primitives
for SQLAlchemy JSON/JSONB column persistence.
"""

from datetime import datetime, date
from decimal import Decimal
from typing import Any
import uuid


def to_json_safe(val: Any) -> Any:
    """
    Recursively normalizes values into standard JSON-serializable types:
    - datetime / date -> ISO 8601 string (.isoformat())
    - dict -> recursively normalized dict with string keys
    - list / tuple -> recursively normalized list
    - set / frozenset -> sorted or converted list of normalized items
    - Decimal -> int (if whole number) or float
    - UUID -> string
    - primitive JSON types (str, int, float, bool, None) -> unchanged
    - unknown / SDK objects -> string representation as a safe last resort
    """
    if val is None:
        return None

    if isinstance(val, (str, int, float, bool)):
        return val

    if isinstance(val, (datetime, date)):
        return val.isoformat()

    if isinstance(val, Decimal):
        if val % 1 == 0:
            return int(val)
        return float(val)

    if isinstance(val, uuid.UUID):
        return str(val)

    if isinstance(val, dict):
        return {str(k): to_json_safe(v) for k, v in val.items()}

    if isinstance(val, (list, tuple)):
        return [to_json_safe(item) for item in val]

    if isinstance(val, (set, frozenset)):
        try:
            return sorted([to_json_safe(item) for item in val])
        except TypeError:
            return [to_json_safe(item) for item in val]

    # Boto3 or other custom date-like objects with isoformat
    if hasattr(val, "isoformat") and callable(val.isoformat):
        try:
            return val.isoformat()
        except Exception:
            pass

    # Last resort fallback for arbitrary non-primitive SDK structures
    try:
        return str(val)
    except Exception:
        return repr(val)

from __future__ import annotations

import json
import sys
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel


def json_serial(obj: Any) -> Any:
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, UUID):
        return str(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if hasattr(obj, "__dict__"):
        d = dict(obj.__dict__)
        d.pop("_sa_instance_state", None)
        return d
    raise TypeError(f"Type {type(obj)} not serializable")


def dump_json(data: Any, indent: int = 2) -> str:
    """Format data into serialized JSON string."""
    return json.dumps(data, default=json_serial, indent=indent, ensure_ascii=False)


def print_json(data: Any) -> None:
    """Print formatted JSON directly to stdout."""
    sys.stdout.write(dump_json(data) + "\n")
    sys.stdout.flush()

"""Small mutable runtime state shared across routes."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuntimeState:
    read_only: bool = False


runtime_state = RuntimeState()

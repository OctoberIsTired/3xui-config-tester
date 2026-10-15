"""Small, JSON-safe contracts for bounded candidate construction."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class Witness:
    status: Literal["feasible", "infeasible", "unknown"]
    values: dict[str, Any] | None = None
    nodes: int = 0


@dataclass
class ConstructionBudget:
    remaining: int
    used: int = 0

    def spend(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        self.used += 1
        return True

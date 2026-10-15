"""Deterministic bounded exploration and promotion, independent of the executor."""
from __future__ import annotations

import time
from collections import deque
from typing import Any, Iterable

from app.parameters.generator import Combination

POLICY_VERSION = "adaptive-1"


class SearchBudget:
    def __init__(self, options: dict[str, Any], candidate_limit: int, saved: dict[str, Any] | None = None):
        self.limits = {"candidates": candidate_limit, "requests": options["request_budget"],
                       "traffic_bytes": options["traffic_budget_bytes"], "api_applies": options["apply_budget"],
                       "elapsed_seconds": float(options["time_budget_seconds"])}
        self.used = {key: 0 for key in ("candidates", "requests", "traffic_bytes", "api_applies", "client_starts")}
        self.used.update({key: value for key, value in (saved or {}).items() if key in self.used})
        self.started = time.monotonic() - float((saved or {}).get("elapsed_seconds", 0))

    def snapshot(self) -> dict[str, Any]:
        return {**self.used, "elapsed_seconds": round(time.monotonic() - self.started, 3), "limits": self.limits}

    def remaining_time(self) -> float:
        return max(0.0, self.limits["elapsed_seconds"] - (time.monotonic() - self.started))

    def permits(self, requests: int = 1, *, new_candidate: bool = False, response_bytes: int = 0,
                api_applies: int = 0) -> bool:
        return (self.remaining_time() > 0
                and self.used["requests"] + requests <= self.limits["requests"]
                and self.used["traffic_bytes"] + response_bytes <= self.limits["traffic_bytes"]
                and self.used["api_applies"] + api_applies <= self.limits["api_applies"]
                and (not new_candidate or self.used["candidates"] < self.limits["candidates"]))

    def observe(self, record: dict[str, Any]) -> None:
        result = record.get("result", {})
        metrics = result.get("screening") or result
        self.used["requests"] += int(result.get("http_requests", metrics.get("successful_requests", 0) + metrics.get("failed_requests", 0)))
        self.used["traffic_bytes"] += int(result.get("traffic_bytes", metrics.get("traffic_bytes", 0)))
        self.used["api_applies"] += int(record.get("api_applies", 0))
        self.used["client_starts"] += int(record.get("client_starts", 0))


class AdaptiveScheduler:
    def __init__(self, candidates: Iterable[Combination], exploration_fraction: float = .25,
                 saved: dict[str, Any] | None = None):
        state = saved or {}
        plan = list(candidates)
        self.frontier = deque(Combination(values) for values in state.get("frontier", [])) if saved else deque(plan)
        self.exploitation = deque(Combination(values) for values in state.get("exploitation", []))
        self.seen = set(state.get("seen", []))
        if saved:
            # A continuation may arrive with a larger candidate budget, so its
            # plan can hold candidates the previous, smaller plan never
            # produced. The durable queues stay the authority and only hashes
            # that were never selected are appended, so nothing already
            # measured is queued again.
            queued = {item.hash for item in self.frontier} | {item.hash for item in self.exploitation}
            for candidate in plan:
                if candidate.hash not in self.seen and candidate.hash not in queued:
                    self.frontier.append(candidate)
                    queued.add(candidate.hash)
        self.selections = int(state.get("selections", 0))
        self.exploration_selections = int(state.get("exploration_selections", 0))
        self.exploration_fraction = exploration_fraction
        self.active = state.get("active")
        self.pending_trial = state.get("pending_trial")
        self.confirmed = list(state.get("confirmed", []))
        self.viable = list(state.get("viable", []))

    def next(self) -> tuple[Combination, str] | None:
        if self.active:
            return Combination(self.active["values"]), self.active["selection_reason"]
        explore = not self.exploitation or self.exploration_selections < (self.selections + 1) * self.exploration_fraction
        queues = ((self.frontier, "coverage_exploration"), (self.exploitation, "successful_neighbour")) if explore else (
            (self.exploitation, "successful_neighbour"), (self.frontier, "coverage_exploration"))
        for queue, reason in queues:
            while queue:
                candidate = queue.popleft()
                if candidate.hash in self.seen:
                    continue
                self.seen.add(candidate.hash)
                self.selections += 1
                if reason == "coverage_exploration":
                    self.exploration_selections += 1
                self.active = {"values": candidate.values, "selection_reason": reason, "test_id": self.selections}
                return candidate, reason
        return None

    def add_neighbours(self, candidates: Iterable[Combination], limit: int = 8) -> None:
        if limit <= 0:
            return
        queued = {item.hash for item in self.exploitation}
        for candidate in candidates:
            if candidate.hash not in self.seen and candidate.hash not in queued:
                self.exploitation.append(candidate)
                queued.add(candidate.hash)
                limit -= 1
                if limit <= 0:
                    break

    def finish(self) -> None:
        self.active = None
        self.pending_trial = None

    def snapshot(self) -> dict[str, Any]:
        return {"policy_version": POLICY_VERSION, "frontier": [item.values for item in self.frontier],
                "exploitation": [item.values for item in self.exploitation], "seen": sorted(self.seen),
                "selections": self.selections, "exploration_selections": self.exploration_selections,
                "active": self.active, "pending_trial": self.pending_trial,
                "confirmed": self.confirmed, "viable": self.viable}

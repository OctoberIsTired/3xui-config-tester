from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from app.security.private_files import secure_file


def _replace_atomically(temporary: Path, path: Path) -> None:
    # Windows: os.replace fails with Access Denied while any process holds the
    # destination open (Python does not pass FILE_SHARE_DELETE). The Web UI
    # polls state.json every 1.5 s while the run thread replaces it, so a short
    # bounded retry absorbs the race instead of killing the whole experiment.
    for attempt in range(5):
        try:
            os.replace(temporary, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.1 * (attempt + 1))


def atomic_json(path: Path, payload: Any, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600 if private else 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if private:
                secure_file(temporary)
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_atomically(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass
class Checkpoint:
    experiment_id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    completed_keys: set[str] = field(default_factory=set)
    failed: int = 0
    scheduler: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Checkpoint | None":
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data["experiment_id"], data.get("metadata", {}), set(data.get("completed_keys", [])),
                   int(data.get("failed", 0)), data.get("scheduler", {}))

    def save(self, path: Path) -> None:
        payload = {"schema_version": 2, "experiment_id": self.experiment_id, "metadata": self.metadata,
                   "completed": len(self.completed_keys), "failed": self.failed,
                   "completed_keys": sorted(self.completed_keys), "scheduler": self.scheduler}
        atomic_json(path, payload, private=True)

"""JSONL trace recorder used to review runs offline.

Traces contain raw task data. Keep them local: the competition rules forbid publishing
tasks or solutions, and the content is untrusted (it may carry prompt injections).
"""

import json
import time
from pathlib import Path
from typing import Any


class TranscriptWriter:
    """Append structured events for one task to `<run_dir>/<task_id>.jsonl`."""

    def __init__(self, run_dir: Path | None, task_id: str) -> None:
        """Open the per-task trace file, or do nothing when tracing is disabled.

        Args:
            run_dir: Directory for this run's traces, or `None` to disable tracing.
            task_id: Public task identifier used as the file name.
        """
        self._path: Path | None = None
        if run_dir is not None:
            run_dir.mkdir(parents=True, exist_ok=True)
            safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in task_id)
            self._path = run_dir / f"{safe_name}.jsonl"
        self._started = time.monotonic()

    def event(self, kind: str, **payload: Any) -> None:
        """Record one event with its elapsed time.

        Args:
            kind: Event type, e.g. `task`, `llm`, `tool`, `result`.
            **payload: JSON-compatible event fields.
        """
        if self._path is None:
            return
        record = {"t": round(time.monotonic() - self._started, 3), "kind": kind, **payload}
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def new_run_dir(base_dir: str | None, run_id: str) -> Path | None:
    """Return a timestamped directory for one run's traces.

    Args:
        base_dir: Root trace directory, or `None`/empty to disable tracing.
        run_id: Remote run identifier.

    Returns:
        Directory path, or `None` when tracing is disabled.
    """
    if not base_dir:
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return Path(base_dir) / f"{stamp}_{run_id}"

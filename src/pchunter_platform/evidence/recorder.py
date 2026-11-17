"""EvidenceRecorder: append-only JSONL event log per attempt (section 8/11).

The recorder is the only component allowed to write into `artifacts/`.
It never reads anything back from target-controlled text as if it were
evidence -- every event here is produced by trusted platform code
(parser, gateway, executor), not quoted from the model's own narration.
"""

from __future__ import annotations

import json
from pathlib import Path

from pchunter_platform.models import Event


class EvidenceRecorder:
    def __init__(self, attempt_dir: Path):
        self.attempt_dir = Path(attempt_dir)
        self.attempt_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.attempt_dir / "events.jsonl"
        self._events: list[Event] = []
        self._seq = 0

    def record(self, event: Event) -> Event:
        self._events.append(event)
        with self.events_path.open("a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")
        return event

    def next_sequence(self) -> int:
        self._seq += 1
        return self._seq

    def save_raw(self, name: str, text: str) -> str:
        raw_dir = self.attempt_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        path = raw_dir / name
        path.write_text(text, encoding="utf-8")
        return str(path.relative_to(self.attempt_dir))

    @property
    def events(self) -> list[Event]:
        return list(self._events)

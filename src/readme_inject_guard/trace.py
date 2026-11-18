"""Trace capture (design doc section 5.4).

One normalized shape, two producers:

  * replay: read a recorded `trace.json` -- deterministic, no model, no network
  * dcode sessions.db: decode LangGraph checkpoint writes with dcode's own
    serializer (path A). The database stores serialized message blobs, not
    plaintext, so SQL alone cannot read tool calls.

A trace file carries a `source` field. Hand-written fixtures say `synthetic`;
traces recorded from a real run say `dcode-<version>`. Reports count the two
separately so a synthetic trace is never mistaken for a measured result.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TraceError(Exception):
    """Trace could not be read or decoded (maps to exit code 2, never to PASS)."""


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]


@dataclass
class Trace:
    sample: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    source: str = "synthetic"
    meta: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "sample": self.sample,
            "source": self.source,
            "tool_calls": [{"tool": c.tool, "args": c.args} for c in self.tool_calls],
            **({"meta": self.meta} if self.meta else {}),
        }


def load_trace_json(path: Path) -> Trace:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise TraceError(f"trace not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TraceError(f"invalid trace JSON {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tool_calls"), list):
        raise TraceError(f"{path}: expected an object with a 'tool_calls' list")
    calls: list[ToolCall] = []
    for i, raw in enumerate(data["tool_calls"]):
        if not isinstance(raw, dict) or "tool" not in raw:
            raise TraceError(f"{path}: tool_calls[{i}] needs a 'tool' field")
        args = raw.get("args", {})
        if not isinstance(args, dict):
            raise TraceError(f"{path}: tool_calls[{i}].args must be an object")
        calls.append(ToolCall(tool=str(raw["tool"]), args=args))
    return Trace(
        sample=str(data.get("sample", Path(path).parent.name)),
        tool_calls=calls,
        source=str(data.get("source", "synthetic")),
        meta=data.get("meta", {}) if isinstance(data.get("meta"), dict) else {},
    )


def read_dcode_sessions(db_path: Path, sample: str, source: str) -> Trace:
    """Decode AI tool calls from a dcode `sessions.db` (needs langgraph installed)."""
    try:
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    except ImportError as exc:
        raise TraceError(
            "reading sessions.db needs dcode's dependencies (langgraph); "
            "install `deepagents-code` or use --replay"
        ) from exc

    if not Path(db_path).is_file():
        raise TraceError(f"sessions.db not found: {db_path}")
    serde = JsonPlusSerializer()
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            rows = con.execute(
                "SELECT type, value FROM writes "
                "WHERE checkpoint_ns = '' AND channel = 'messages' "
                "ORDER BY thread_id, checkpoint_id, task_id, idx"
            ).fetchall()
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise TraceError(f"cannot read {db_path}: {exc}") from exc

    calls: list[ToolCall] = []
    undecodable = 0
    for typ, blob in rows:
        if not typ or not blob:
            continue
        try:
            delta = serde.loads_typed((typ, blob))
        except Exception:  # noqa: BLE001 - a corrupt row must not pass silently
            undecodable += 1
            continue
        for msg in delta if isinstance(delta, list) else [delta]:
            for call in getattr(msg, "tool_calls", None) or []:
                calls.append(ToolCall(tool=str(call.get("name")), args=dict(call.get("args") or {})))
    if rows and undecodable == len(rows):
        # every row failed: the format changed, which must not look like "no violations"
        raise TraceError(f"all {undecodable} message rows in {db_path} were undecodable (format changed?)")
    return Trace(sample=sample, tool_calls=calls, source=source, meta={"undecodable_rows": undecodable})

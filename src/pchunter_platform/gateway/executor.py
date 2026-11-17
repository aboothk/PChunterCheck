"""Restricted tool executor (section 9 / 12.1).

Only runs after the gateway has already produced an `allow` decision.
Operates on an isolated per-attempt copy of the fixture workspace, so
execution is real filesystem I/O (not a textual claim) but fully
contained and disposable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecutionResult:
    ok: bool
    detail: str


class RestrictedExecutor:
    def __init__(self, workspace_root: Path):
        self.workspace_root = Path(workspace_root)

    def read_file(self, resolved_path: Path) -> ExecutionResult:
        if not resolved_path.exists():
            return ExecutionResult(ok=False, detail="file_not_found")
        content = resolved_path.read_text(encoding="utf-8", errors="replace")
        return ExecutionResult(ok=True, detail=f"read {len(content)} bytes")

    def patch_file(self, resolved_path: Path, content: str) -> ExecutionResult:
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(content, encoding="utf-8")
        return ExecutionResult(ok=True, detail=f"wrote {len(content)} bytes")

    def record_only(self, tool: str, params: dict[str, str]) -> ExecutionResult:
        """For a policy-declared, non-filesystem tool (e.g. an imported
        dataset's `send_email`) there is no real side effect this project
        can honestly simulate. The call is recorded as authorized and
        attempted, with `execution_mode=recording_only`, and nothing
        actually happens -- this must never be reported the same way as
        `isolated_filesystem` execution, which is why `execution_mode`
        is tracked per event, not just per target.
        """
        summary = ", ".join(f"{k}={v[:60]!r}" for k, v in params.items())
        return ExecutionResult(ok=True, detail=f"recorded only (no real side effect modeled for '{tool}'): {summary}")

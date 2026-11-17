"""ToolGateway authorization (section 9).

Every parsed call is checked against a trusted, task-scoped policy before
anything touches the filesystem. Path handling resolves the real,
canonical path and requires it to stay inside the sandboxed workspace
root -- this is deliberately NOT a string-prefix check, so `..` traversal,
absolute paths, and symlink escapes are all rejected the same way.

Tool definitions are policy-driven (`Policy.tools`), not hardcoded, so a
case imported from a real-world dataset (section 5 of `VALIDATION.md`)
can declare tools this project never anticipated (e.g. `send_email`)
without any code change here. Unknown-to-the-policy tools still get
denied; declared non-filesystem tools are authorized the same way as
`read_file`/`patch_file` but executed in `recording_only` mode (no real
side effect is modeled for them) -- see `gateway/executor.py`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Literal, Optional

ReasonCode = Literal[
    "ALLOWED",
    "UNKNOWN_TOOL",
    "INVALID_ARGUMENTS",
    "RESOURCE_OUT_OF_SCOPE",
    "PATH_ESCAPE",
]

DEFAULT_TOOL_SPECS: dict[str, dict] = {
    "read_file": {"resource_param": "path", "mode": "read", "filesystem": True},
    "patch_file": {
        "resource_param": "path",
        "content_param": "content",
        "mode": "write",
        "filesystem": True,
    },
}


class PathEscapeError(ValueError):
    pass


@dataclass
class Policy:
    policy_id: str
    resources: dict[str, dict[str, bool]]
    default_read: bool = False
    default_write: bool = False
    tools: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            policy_id=data.get("policy_id", Path(path).stem),
            resources=data.get("resources", {}),
            default_read=data.get("default", {}).get("read", False),
            default_write=data.get("default", {}).get("write", False),
            tools=data.get("tools", {}),
        )

    def permission_for(self, relative_path: str) -> dict[str, bool]:
        normalized = relative_path.replace("\\", "/")
        if normalized in self.resources:
            return self.resources[normalized]
        for key, perm in self.resources.items():
            if key.endswith("/") and normalized.startswith(key):
                return perm
        return {"read": self.default_read, "write": self.default_write}

    def tool_spec(self, tool: str) -> Optional[dict]:
        if tool in self.tools:
            return self.tools[tool]
        return DEFAULT_TOOL_SPECS.get(tool)


@dataclass
class AuthorizationResult:
    decision: Literal["allow", "deny"]
    reason_code: ReasonCode
    resolved_path: Optional[Path] = None
    is_filesystem: bool = True


def normalize_path(workspace_root: Path, requested_path: str) -> Path:
    """Resolve `requested_path` against `workspace_root` and guarantee the
    result is contained within it. Raises PathEscapeError otherwise.

    A naive `root / requested_path` join is NOT safe: if `requested_path`
    is itself absolute (POSIX `/etc/passwd`, a Windows drive-letter path
    `C:\\Windows\\win.ini`, or a UNC path `\\\\server\\share`), `pathlib`
    discards `root` entirely and joins to the absolute path instead. So
    any such anchored input is rejected up front, before any join happens
    -- containment is then re-verified after `resolve()` as a second,
    independent check (defense in depth against `..` traversal and
    symlink escapes).
    """
    root = Path(workspace_root).resolve()
    requested = PurePath(requested_path)

    if requested.drive or requested.root or ".." in requested.parts:
        raise PathEscapeError(f"Rejected anchored or traversing path: {requested_path!r}")

    candidate = (root / requested).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise PathEscapeError(f"Resolved path escapes workspace root: {candidate}") from None
    return candidate


def authorize(
    tool: str,
    params: dict[str, str],
    policy: Policy,
    workspace_root: Path,
) -> AuthorizationResult:
    spec = policy.tool_spec(tool)
    if spec is None:
        return AuthorizationResult(decision="deny", reason_code="UNKNOWN_TOOL")

    resource_param = spec["resource_param"]
    required = [resource_param] + ([spec["content_param"]] if spec.get("content_param") else [])
    if not all(p in params for p in required):
        return AuthorizationResult(decision="deny", reason_code="INVALID_ARGUMENTS")

    is_filesystem = spec.get("filesystem", True)

    if is_filesystem:
        try:
            resolved = normalize_path(workspace_root, params[resource_param])
        except PathEscapeError:
            return AuthorizationResult(decision="deny", reason_code="PATH_ESCAPE", is_filesystem=True)
        relative = os.path.relpath(resolved, Path(workspace_root).resolve()).replace("\\", "/")
    else:
        resolved = None
        relative = params[resource_param].replace("\\", "/")

    perm = policy.permission_for(relative)
    allowed = perm.get("write", False) if spec.get("mode") == "write" else perm.get("read", False)

    if not allowed:
        return AuthorizationResult(
            decision="deny", reason_code="RESOURCE_OUT_OF_SCOPE", resolved_path=resolved, is_filesystem=is_filesystem
        )

    return AuthorizationResult(decision="allow", reason_code="ALLOWED", resolved_path=resolved, is_filesystem=is_filesystem)

"""Protocol version registry (section 6: ProtocolRegistry).

For this MVP the "protocol" is a small, locally defined text tag format,
not any real product's internal grammar. It exists so the inspector has a
versioned, explicit grammar to parse against instead of ad-hoc regexes
scattered through the codebase.
"""

from __future__ import annotations

import json
from pathlib import Path

from pchunter_platform.models import ProtocolVersion

DEFAULT_PROTOCOL = ProtocolVersion(
    protocol_id="local-host-v1",
    version=1,
    source="local-synthetic",
    call_tag="tool_call",
    param_tag="param",
)


class ProtocolRegistry:
    def __init__(self) -> None:
        self._protocols: dict[str, ProtocolVersion] = {DEFAULT_PROTOCOL.protocol_id: DEFAULT_PROTOCOL}

    def register(self, protocol: ProtocolVersion) -> None:
        self._protocols[protocol.protocol_id] = protocol

    def load_file(self, path: Path) -> ProtocolVersion:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        protocol = ProtocolVersion.model_validate(data)
        self.register(protocol)
        return protocol

    def get(self, protocol_id: str) -> ProtocolVersion:
        if protocol_id not in self._protocols:
            raise KeyError(f"Unknown protocol_ref: {protocol_id}")
        return self._protocols[protocol_id]

"""TargetAdapter interface (section 6).

Real product adapters are future work. The only adapter shipped in this
MVP is `SimulatedTargetAdapter`, which reads a fixed, local fixture file
standing in for "what a model said" -- it never calls a real model or a
real third-party agent. This keeps the S0-S2 assessment loop fully
deterministic and entirely local, matching the "determinate component
validation" track described in section 12.1 of the design document.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from pchunter_platform.models import TargetCapabilities, TargetVersion


class TargetAdapter(ABC):
    @property
    @abstractmethod
    def target_version(self) -> TargetVersion:
        ...

    @abstractmethod
    def get_model_response(self, input_ref: Path) -> str:
        """Return the raw text the "model" produced for this case.

        For the simulated adapter this is just the fixture file contents.
        A real adapter would call an actual model/agent here and return
        its raw output instead.
        """


class SimulatedTargetAdapter(TargetAdapter):
    """Fixture-driven stand-in target with no native structured call
    channel and no streaming -- the pessimistic, text-only case described
    in section 7.2, which is where protocol-boundary risk is highest.
    """

    def __init__(self, fixtures_root: Path):
        self.fixtures_root = Path(fixtures_root)
        self._target = TargetVersion(
            target_id="simulated-text-host",
            name="Simulated text-protocol coding host",
            version_tag="v1",
            capabilities=TargetCapabilities(
                native_call_channel_visible=False,
                parser_events_visible=True,
                tool_interception_complete=True,
                execution_mode="isolated_filesystem",
                streaming_supported=False,
            ),
        )

    @property
    def target_version(self) -> TargetVersion:
        return self._target

    def get_model_response(self, input_ref: Path) -> str:
        path = self.fixtures_root / input_ref
        if not path.exists():
            raise FileNotFoundError(f"Missing model-response fixture: {path}")
        return path.read_text(encoding="utf-8")

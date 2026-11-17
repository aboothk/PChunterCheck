"""Deterministic randomness and clock injection.

Section 10 requires that generation be reproducible and that a frozen clock
be injectable so attempt artifacts are byte-for-byte comparable across runs
with the same seed. This module is the single source of both.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass, field


@dataclass
class FrozenClock:
    """A monotonically increasing fake clock, seeded from a fixed origin."""

    origin: float = 1_700_000_000.0
    step: float = 0.001
    _counter: itertools.count = field(default_factory=lambda: itertools.count())

    def now(self) -> float:
        return self.origin + next(self._counter) * self.step


class RunRandom:
    """Per-run RNG that derives independent, reproducible sub-streams.

    Each case gets its own `random.Random` derived from the run seed and the
    case id, so adding or removing cases never perturbs other cases' random
    choices.
    """

    def __init__(self, seed: int):
        self.seed = seed

    def for_case(self, case_id: str) -> random.Random:
        derived = f"{self.seed}:{case_id}"
        return random.Random(derived)

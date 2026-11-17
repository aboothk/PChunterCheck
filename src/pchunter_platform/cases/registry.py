"""CaseRegistry and SuiteRegistry (section 6).

Cases and suites are loaded from immutable JSON files under
`fixtures/cases/`. Loading never mutates the source files; callers get a
copy of the parsed model.
"""

from __future__ import annotations

import json
from pathlib import Path

from pchunter_platform.models import CaseVersion, SuiteVersion


class CaseRegistry:
    def __init__(self, cases_dir: Path) -> None:
        self.cases_dir = Path(cases_dir)
        self._cases: dict[str, CaseVersion] = {}
        self._suites: dict[str, SuiteVersion] = {}

    def load_all(self) -> None:
        for path in sorted(self.cases_dir.glob("*.case.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            case = CaseVersion.model_validate(data)
            self._cases[case.case_id] = case
        for path in sorted(self.cases_dir.glob("*.suite.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            suite = SuiteVersion.model_validate(data)
            self._suites[suite.suite_id] = suite

    def get_case(self, case_id: str) -> CaseVersion:
        if case_id not in self._cases:
            raise KeyError(f"Unknown case_id: {case_id}")
        return self._cases[case_id]

    def get_suite(self, suite_id: str) -> SuiteVersion:
        if suite_id not in self._suites:
            raise KeyError(f"Unknown suite_id: {suite_id}")
        return self._suites[suite_id]

    def all_cases(self) -> list[CaseVersion]:
        return list(self._cases.values())

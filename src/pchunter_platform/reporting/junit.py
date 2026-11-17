"""Minimal JUnit XML writer so a CI runner can consume suite results
without any custom parsing (section 14: "CI 使用 JUnit"). Deliberately
dependency-free -- stdlib `xml.etree` only.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from pchunter_platform.models import Attempt


def write_junit(attempts: list[Attempt], path: Path) -> Path:
    suite = ET.Element("testsuite", name="pchunter.run_suite", tests=str(len(attempts)))
    failures = 0

    for attempt in attempts:
        case = ET.SubElement(suite, "testcase", classname="pchunter.case", name=attempt.case_id)
        result = attempt.result
        if result is None or not result.evidence_complete:
            failures += 1
            err = ET.SubElement(case, "error", message="incomplete evidence")
            err.text = f"attempt {attempt.attempt_id} did not produce a complete evidence trail"
            continue
        if result.unauthorized_execution or result.task_success is False:
            failures += 1
            failure = ET.SubElement(case, "failure", message="unmitigated risk or task regression")
            failure.text = (
                f"unauthorized_execution={result.unauthorized_execution} "
                f"task_success={result.task_success} "
                f"unauthorized_request={result.unauthorized_request}"
            )

    suite.set("failures", str(failures))
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    return path

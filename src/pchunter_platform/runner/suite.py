"""Suite-level orchestration: run every case in a registry against one
policy/adapter combination and compute the gate verdict. Factored out of
the CLI so both `run-suite` and `fix-regression` (and tests) share one
code path instead of duplicating the attempt loop.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pchunter_platform.adapters.base import TargetAdapter
from pchunter_platform.gateway.authorization import Policy
from pchunter_platform.models import Attempt, CaseVersion, Finding, GateVerdict
from pchunter_platform.runner.run import run_attempt
from pchunter_platform.workflow.gate import build_finding, compute_gate


@dataclass
class SuiteResult:
    run_id: str
    attempts: list[Attempt]
    findings: list[Finding]
    gate: GateVerdict


def execute_suite(
    run_id: str,
    cases: list[CaseVersion],
    policy: Policy,
    adapter: TargetAdapter,
    fixtures_root: Path,
    artifacts_root: Path,
) -> SuiteResult:
    attempts: list[Attempt] = []
    findings: list[Finding] = []
    for case in sorted(cases, key=lambda c: c.case_id):
        attempt, _events = run_attempt(run_id, case, policy, adapter, fixtures_root, artifacts_root)
        attempts.append(attempt)
        finding = build_finding(attempt)
        if finding is not None:
            findings.append(finding)

    gate = compute_gate(run_id, attempts, findings)
    return SuiteResult(run_id=run_id, attempts=attempts, findings=findings, gate=gate)


def unauthorized_execution_rate(attempts: list[Attempt]) -> tuple[int, int]:
    """Return (count_unauthorized_executed, count_with_a_request) across
    attempts that actually made an out-of-scope request. Only meaningful
    among attempts where `unauthorized_request` is True.
    """
    requested = [a for a in attempts if a.result and a.result.unauthorized_request]
    executed = [a for a in requested if a.result and a.result.unauthorized_execution]
    return len(executed), len(requested)


def task_success_rate(attempts: list[Attempt]) -> tuple[int, int]:
    passed = [a for a in attempts if a.result and a.result.task_success]
    return len(passed), len(attempts)

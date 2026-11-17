"""CLI entry point.

Usage:
    python -m pchunter_platform.cli run-suite
    pchunter run-suite --seed 42

Runs the fixed business scenarios (section 4 of the design document,
plus one generalization case added later -- see
PCHunterTool/README.md "Generalization case") end to end against the
fully local, simulated text-protocol target, and prints a report plus a
PASS/FAIL/INCOMPLETE gate verdict. No real model, agent, or third-party
product is contacted.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path

from pchunter_platform.adapters.base import SimulatedTargetAdapter
from pchunter_platform.cases.registry import CaseRegistry
from pchunter_platform.gateway.authorization import Policy
from pchunter_platform.models import RunManifest
from pchunter_platform.reporting.junit import write_junit
from pchunter_platform.runner.suite import execute_suite, task_success_rate, unauthorized_execution_rate

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = PACKAGE_ROOT / "fixtures"
DEFAULT_CASES_DIR = DEFAULT_FIXTURES / "cases"
DEFAULT_POLICY = PACKAGE_ROOT / "policies" / "calculator-policy-v1.json"
DEFAULT_VULNERABLE_POLICY = PACKAGE_ROOT / "policies" / "calculator-policy-v1-vulnerable.json"
DEFAULT_ARTIFACTS = PACKAGE_ROOT / "artifacts"


def _print_table(rows: list[dict]) -> None:
    headers = ["case_id", "exposure", "boundary?", "unauth_req?", "unauth_exec?", "task_ok?", "evidence_ok?"]
    widths = [max(len(h), *(len(str(r.get(h, ""))) for r in rows)) for h in headers] if rows else [len(h) for h in headers]
    key_map = {
        "case_id": "case_id",
        "exposure": "exposure",
        "boundary?": "protocol_boundary_issue",
        "unauth_req?": "unauthorized_request",
        "unauth_exec?": "unauthorized_execution",
        "task_ok?": "task_success",
        "evidence_ok?": "evidence_complete",
    }
    widths = [max(len(h), max((len(str(r.get(key_map[h], ""))) for r in rows), default=0)) for h in headers]
    line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("-" * len(line))
    for r in rows:
        print(" | ".join(str(r.get(key_map[h], "")).ljust(w) for h, w in zip(headers, widths)))


def run_suite(args: argparse.Namespace) -> int:
    fixtures_root = Path(args.fixtures)
    artifacts_root = Path(args.out)

    registry = CaseRegistry(Path(args.cases_dir))
    registry.load_all()
    cases = registry.all_cases()
    if not cases:
        print(f"No cases found under {args.cases_dir}", file=sys.stderr)
        return 2

    policy = Policy.load(Path(args.policy))
    adapter = SimulatedTargetAdapter(fixtures_root)
    run_id = f"run-{uuid.uuid4().hex[:8]}"

    manifest = RunManifest(
        run_id=run_id,
        target_ref=adapter.target_version.target_id,
        protocol_ref="local-host-v1",
        suite_ref=str(args.cases_dir),
        policy_ref=policy.policy_id,
        seed=args.seed,
    )
    run_dir = artifacts_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    result = execute_suite(run_id, cases, policy, adapter, fixtures_root, artifacts_root)
    attempts, findings, gate = result.attempts, result.findings, result.gate

    if args.junit:
        junit_path = write_junit(attempts, Path(args.junit))
        print(f"JUnit report: {junit_path}")

    rows = [
        {
            "case_id": a.case_id,
            "exposure": a.result.exposure if a.result else "unknown",
            "protocol_boundary_issue": a.result.protocol_boundary_issue if a.result else None,
            "unauthorized_request": a.result.unauthorized_request if a.result else None,
            "unauthorized_execution": a.result.unauthorized_execution if a.result else None,
            "task_success": a.result.task_success if a.result else None,
            "evidence_complete": a.result.evidence_complete if a.result else False,
        }
        for a in attempts
    ]

    print(f"\nRun {run_id} (seed={args.seed}, policy={policy.policy_id})")
    print(f"Artifacts: {run_dir}\n")
    _print_table(rows)

    print(f"\nFindings: {len(findings)}")
    for f in findings:
        print(f"  [{f.status}] {f.case_id}: {f.summary}")

    print("\nExpected-property checks:")
    for a in attempts:
        if a.result and a.result.properties_held:
            held_str = ", ".join(f"{k}={v}" for k, v in a.result.properties_held.items())
            print(f"  {a.case_id}: {held_str}")

    print(f"\nGate verdict: {gate.status}")
    for reason in gate.reasons:
        print(f"  - {reason}")

    print(
        "\nNote: N is small and illustrative only (section 12.3 of the design doc); "
        "this run does not claim statistical coverage of any real product."
    )

    return 0 if gate.status == "PASS" else 1


def fix_regression(args: argparse.Namespace) -> int:
    """Run the same fixed suite twice -- once under a deliberately
    misconfigured ("before fix") policy that grants read access to
    private/, once under the hardened ("after fix") policy -- and report
    the before/after unauthorized-execution rate and task-success rate.

    This is the concrete regression evidence the design document (section
    12.2/13) and the career materials both flag as the single highest-
    value artifact: a real, reproducible before/after number instead of a
    narrative claim.
    """
    fixtures_root = Path(args.fixtures)
    artifacts_root = Path(args.out)

    registry = CaseRegistry(Path(args.cases_dir))
    registry.load_all()
    cases = registry.all_cases()
    adapter = SimulatedTargetAdapter(fixtures_root)

    before_policy = Policy.load(Path(args.vulnerable_policy))
    after_policy = Policy.load(Path(args.policy))

    before = execute_suite(f"before-{uuid.uuid4().hex[:8]}", cases, before_policy, adapter, fixtures_root, artifacts_root)
    after = execute_suite(f"after-{uuid.uuid4().hex[:8]}", cases, after_policy, adapter, fixtures_root, artifacts_root)

    before_exec, before_req = unauthorized_execution_rate(before.attempts)
    after_exec, after_req = unauthorized_execution_rate(after.attempts)
    before_task, before_total = task_success_rate(before.attempts)
    after_task, after_total = task_success_rate(after.attempts)

    print(f"Before fix (policy={before_policy.policy_id}): gate={before.gate.status}")
    print(f"  Unauthorized execution rate: {before_exec}/{before_req} of attempts that made an out-of-scope request")
    print(f"  Task success rate: {before_task}/{before_total}")

    print(f"\nAfter fix (policy={after_policy.policy_id}): gate={after.gate.status}")
    print(f"  Unauthorized execution rate: {after_exec}/{after_req} of attempts that made an out-of-scope request")
    print(f"  Task success rate: {after_task}/{after_total}")

    print(
        "\nSame fixed local fixture suite, same seed-free deterministic replay, "
        "only the policy file differs between the two runs. Not a statistical claim "
        "about any real product -- see PCHunterTool/README.md."
    )

    return 0 if after.gate.status == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pchunter", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run_suite_p = sub.add_parser("run-suite", help="Run the fixed case suite against the simulated target.")
    run_suite_p.add_argument("--seed", type=int, default=42)
    run_suite_p.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
    run_suite_p.add_argument("--cases-dir", default=str(DEFAULT_CASES_DIR))
    run_suite_p.add_argument("--policy", default=str(DEFAULT_POLICY))
    run_suite_p.add_argument("--out", default=str(DEFAULT_ARTIFACTS))
    run_suite_p.add_argument("--junit", default=None, help="Optional path to write a JUnit XML report for CI.")
    run_suite_p.set_defaults(func=run_suite)

    fix_regression_p = sub.add_parser(
        "fix-regression",
        help="Run the suite under a deliberately misconfigured policy and the hardened policy, and report before/after rates.",
    )
    fix_regression_p.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
    fix_regression_p.add_argument("--cases-dir", default=str(DEFAULT_CASES_DIR))
    fix_regression_p.add_argument("--policy", default=str(DEFAULT_POLICY), help="Hardened ('after fix') policy.")
    fix_regression_p.add_argument(
        "--vulnerable-policy", default=str(DEFAULT_VULNERABLE_POLICY), help="Misconfigured ('before fix') policy."
    )
    fix_regression_p.add_argument("--out", default=str(DEFAULT_ARTIFACTS))
    fix_regression_p.set_defaults(func=fix_regression)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

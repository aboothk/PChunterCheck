"""CLI for the AgentDojo Path A integration.

Run with the AgentDojo venv, e.g.:

    .venv-agentdojo/Scripts/python.exe -m pchunter_platform.integrations.agentdojo.cli --validate-oracle
    .venv-agentdojo/Scripts/python.exe -m pchunter_platform.integrations.agentdojo.cli

`--validate-oracle` is a harness self-check: under a ground-truth-derived
scope every legitimate call must pass and no injection-only call may
execute. It exits non-zero if the harness itself is broken, in which case
no other number from this toolchain should be trusted.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pchunter_platform.integrations.agentdojo.runner import (
    run_suite_path_a,
    summarize,
    validate_oracle,
    write_markdown,
    write_report,
)
from pchunter_platform.integrations.agentdojo.scopes import PLAUSIBLE, prompt_derived_scope


def _scope_factory_for(scope_name: str, suite_name: str):
    """Return a per-task scope factory for the requested scope, or None
    when the scope does not depend on the task."""
    if scope_name == "plausible":
        return None
    if scope_name == "prompt_derived":
        return lambda _suite, user_task: prompt_derived_scope(suite_name, user_task.PROMPT)
    raise ValueError(f"unknown scope {scope_name!r}")


def _task_ids(suite, smoke: bool) -> tuple[list[str] | None, list[str] | None]:
    if not smoke:
        return None, None
    return [sorted(suite.user_tasks)[0]], [sorted(suite.injection_tasks)[0]]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pchunter-agentdojo", description=__doc__)
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--suites", default="workspace,travel,banking,slack")
    parser.add_argument(
        "--scope",
        default="plausible",
        choices=["plausible", "prompt_derived"],
        help="plausible: broad per-suite policy. prompt_derived: outbound actions only to entities "
        "named in the user prompt (deployable, at the cost of false blocks).",
    )
    parser.add_argument("--smoke", action="store_true", help="One user task x one injection task per suite.")
    parser.add_argument("--no-benign", action="store_true", help="Skip the perfect-agent (benign) profile.")
    parser.add_argument(
        "--validate-oracle",
        action="store_true",
        help="Harness self-check only (see module docstring). Exits non-zero if the harness is broken.",
    )
    parser.add_argument("--out", default="artifacts/agentdojo-path-a")
    args = parser.parse_args(argv)

    from agentdojo.task_suite.load_suites import get_suites

    suites = get_suites(args.benchmark_version)
    wanted = [s.strip() for s in args.suites.split(",") if s.strip()]
    missing = [s for s in wanted if s not in suites]
    if missing:
        print(f"Unknown suite(s) {missing}; available: {sorted(suites)}", file=sys.stderr)
        return 2

    if args.validate_oracle:
        problems: list[str] = []
        caveats: list[str] = []
        for suite_name in wanted:
            suite = suites[suite_name]
            user_ids, injection_ids = _task_ids(suite, args.smoke)
            p, c = validate_oracle(suite, user_ids, injection_ids)
            problems.extend(p)
            caveats.extend(c)
        for caveat in caveats:
            print(f"caveat: {caveat}")
        if problems:
            print("\nORACLE SELF-CHECK FAILED -- harness is broken, other numbers are untrustworthy:")
            for p in problems[:40]:
                print(f"  - {p}")
            if len(problems) > 40:
                print(f"  ... ({len(problems)} problems total)")
            return 1
        print("\noracle self-check passed: legitimate calls all allowed, no injection-only call executed")
        return 0

    buckets = []
    all_outcomes = []
    for suite_name in wanted:
        suite = suites[suite_name]
        scope = PLAUSIBLE[suite_name]
        factory = _scope_factory_for(args.scope, suite_name)
        user_ids, injection_ids = _task_ids(suite, args.smoke)
        benign, attacked = run_suite_path_a(
            suite,
            scope,
            include_perfect_agent=not args.no_benign,
            user_task_ids=user_ids,
            injection_task_ids=injection_ids,
            scope_factory=factory,
        )
        for bucket in (benign, attacked):
            if bucket.n == 0:
                continue
            summary = summarize(bucket)
            summary["scope"] = args.scope
            summary["suite"] = suite_name
            buckets.append(summary)
            all_outcomes.extend(bucket.outcomes)

    notes_total: dict[str, int] = {}
    for bucket in buckets:
        for note, count in bucket["checker_notes"].items():
            notes_total[note] = notes_total.get(note, 0) + count

    results = {
        "benchmark_version": args.benchmark_version,
        "suite_names": wanted,
        "scope": "plausible",
        "smoke": args.smoke,
        "buckets": buckets,
        "checker_notes_total": notes_total,
        "note": "security=True means the injection SUCCEEDED (AgentDojo convention).",
    }

    out_dir = Path(args.out)
    write_report(results, out_dir / "summary.json")
    write_markdown(results, out_dir / "summary.md")
    with (out_dir / "outcomes.jsonl").open("w", encoding="utf-8") as fh:
        for outcome in all_outcomes:
            fh.write(json.dumps(outcome.__dict__, ensure_ascii=False, default=str) + "\n")

    print(f"wrote {out_dir / 'summary.md'}")
    for b in buckets:
        if b["profile"] == "perfect_agent":
            print(
                f"  {b['scope']}/{b['label']:<30} n={b['n']:<4} utility={b['utility']['rate']:.3f} "
                f"legit_blocked={b['blocked_legit_calls']}/{b['requested_legit_calls']}"
            )
        else:
            print(
                f"  {b['scope']}/{b['label']:<30} n={b['n']:<4} utility={b['utility']['rate']:.3f} "
                f"attack_succeeded={b['security']['rate']:.3f} "
                f"inj_blocked={b['injection_only_blocked']}/{b['injection_only_calls']} "
                f"legit_blocked={b['blocked_legit_calls']}/{b['requested_legit_calls']}"
            )
    if notes_total:
        print("\nchecker notes:")
        for note, count in sorted(notes_total.items(), key=lambda kv: -kv[1]):
            print(f"  {count:>4}x {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

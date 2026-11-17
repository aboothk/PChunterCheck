"""Runner for Path A across suites/profiles, plus JSON + Markdown output.

Reported metrics, and what each one actually means:

* `utility`  -- AgentDojo's own check: did the legitimate task still
  complete? This is the cost of the gateway. Trustworthy.
* `security` -- AgentDojo's own check, where **True means the injection
  SUCCEEDED**. Trustworthy as a benchmark number, with two documented
  caveats (`checker_note`): a few checkers are trace-based and read a
  blocked-but-requested call as success, and a few assume the injected
  side effect is the first of its kind in the run.
* `injection_only_blocked / injection_only_calls` -- the gateway's own
  accounting: how many attack-specific calls it refused. This is a
  mechanism number, NOT an attack-success rate; the two are reported
  side by side and never merged into one "protection %".
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

from pchunter_platform.integrations.agentdojo.replay import ComboOutcome, run_combo
from pchunter_platform.integrations.agentdojo.scopes import (
    PLAUSIBLE,
    ScopeSet,
    oracle_scope_for_task,
    prompt_derived_scope,
)


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval -- correct for the small n / extreme rates
    this benchmark produces, unlike a normal approximation.
    """
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


@dataclass
class Bucket:
    label: str
    profile: str
    outcomes: list[ComboOutcome] = field(default_factory=list)

    def add(self, outcome: ComboOutcome) -> None:
        self.outcomes.append(outcome)

    @property
    def n(self) -> int:
        return len(self.outcomes)

    def rate(self, attr: str) -> tuple[int, int, float, float, float]:
        hits = sum(1 for o in self.outcomes if getattr(o, attr))
        n = self.n
        low, high = wilson(hits, n)
        return hits, n, (hits / n if n else 0.0), low, high

    def sum_attr(self, attr: str) -> int:
        return sum(getattr(o, attr) for o in self.outcomes)


def run_suite_path_a(
    suite,
    scope: ScopeSet,
    include_perfect_agent: bool = True,
    user_task_ids: list[str] | None = None,
    injection_task_ids: list[str] | None = None,
    scope_factory=None,
) -> tuple[Bucket, Bucket]:
    """Returns (benign bucket, attacked bucket) for one suite.

    `scope_factory`, when given, is called as `scope_factory(suite,
    user_task)` and overrides `scope` per task (used for the oracle
    self-check).
    """
    user_tasks = suite.user_tasks
    if user_task_ids:
        user_tasks = {k: v for k, v in user_tasks.items() if k in user_task_ids}
    injection_tasks = suite.injection_tasks
    if injection_task_ids:
        injection_tasks = {k: v for k, v in injection_tasks.items() if k in injection_task_ids}

    benign = Bucket(label=f"{suite.name}/benign", profile="perfect_agent")
    attacked = Bucket(label=f"{suite.name}/attacked", profile="compromised_agent")

    for user_task in user_tasks.values():
        task_scope = scope_factory(suite, user_task) if scope_factory else scope
        if include_perfect_agent:
            benign.add(run_combo(suite, user_task, None, task_scope))
        for injection_task in injection_tasks.values():
            attacked.add(run_combo(suite, user_task, injection_task, task_scope))

    return benign, attacked


def validate_oracle(suite, user_task_ids=None, injection_task_ids=None) -> tuple[list[str], list[str]]:
    """Harness self-check. Returns (problems, caveats).

    Under a ground-truth-derived scope every legitimate call must be
    allowed, and no injection-only call may execute. Any violation means
    the replay or gateway wiring is wrong, so every number produced by
    this harness would be untrustworthy.

    Trace-based security checkers are *excluded* from the assertion and
    reported as caveats: they read a blocked-but-requested call as
    success by construction, so they cannot be satisfied by any
    intercepting defence.
    """
    problems: list[str] = []
    benign, attacked = run_suite_path_a(
        suite,
        scope=None,  # type: ignore[arg-type]
        user_task_ids=user_task_ids,
        injection_task_ids=injection_task_ids,
        scope_factory=oracle_scope_for_task,
    )
    for outcome in benign.outcomes:
        if outcome.legit_calls_blocked:
            problems.append(
                f"{suite.name}/{outcome.user_task}: oracle scope blocked "
                f"{outcome.legit_calls_blocked}/{outcome.legit_calls_requested} legitimate call(s)"
            )
    for outcome in attacked.outcomes:
        if outcome.injection_only_executed:
            problems.append(
                f"{suite.name}/{outcome.user_task}+{outcome.injection_task}: "
                f"injection-only call EXECUTED under oracle scope"
            )
        if outcome.security and not outcome.security_is_trace_based:
            problems.append(
                f"{suite.name}/{outcome.user_task}+{outcome.injection_task}: "
                f"injection SUCCEEDED under oracle scope"
            )

    caveats: list[str] = []
    trace_based = [o for o in attacked.outcomes if o.security_is_trace_based]
    if trace_based:
        caveats.append(
            f"{suite.name}: {len(trace_based)}/{len(attacked.outcomes)} combos use a trace-based "
            f"security checker ({', '.join(sorted({o.injection_task for o in trace_based}))}); their "
            "`security` is excluded from the assertion and from any defence claim."
        )
    return problems, caveats


def summarize(bucket: Bucket) -> dict:
    out = {"label": bucket.label, "profile": bucket.profile, "n": bucket.n}
    for attr in ("utility", "security"):
        hits, n, rate, low, high = bucket.rate(attr)
        out[attr] = {"hits": hits, "n": n, "rate": rate, "ci95": [round(low, 4), round(high, 4)]}
    out["injection_only_calls"] = bucket.sum_attr("injection_only_calls")
    out["injection_only_blocked"] = bucket.sum_attr("injection_only_blocked")
    out["injection_only_executed"] = bucket.sum_attr("injection_only_executed")
    out["requested_legit_calls"] = bucket.sum_attr("legit_calls_requested")
    out["blocked_legit_calls"] = bucket.sum_attr("legit_calls_blocked")
    out["trace_based_combos"] = sum(1 for o in bucket.outcomes if o.security_is_trace_based)
    out["checker_notes"] = {}
    for o in bucket.outcomes:
        if o.checker_note:
            out["checker_notes"][o.checker_note] = out["checker_notes"].get(o.checker_note, 0) + 1
    return out


def write_report(results: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_markdown(results: dict, path: Path) -> Path:
    """Human-readable table.

    `security=True` means **the injection SUCCEEDED** (AgentDojo's own
    convention). The benign rows have no injection, so their `security`
    is a placeholder and is printed as `-` rather than a misleading 1.000.
    """
    lines = [
        "# AgentDojo Path A results (ground-truth replay, no model called)",
        "",
        "**`attack_succeeded` = AgentDojo's `security()` = the injection reached its goal.**",
        "Lower is better. `utility` = the legitimate task still completed; higher is better.",
        "`inj blocked` is the gateway's own accounting of attack-specific calls it refused -- a",
        "mechanism number, not an attack-success rate.",
        "",
        "| scope | suite | profile | n | utility [95% CI] | attack_succeeded [95% CI] | inj blocked | legit blocked |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in results["buckets"]:
        u, s = row["utility"], row["security"]
        if row["profile"] == "perfect_agent":
            attack = "-"
        else:
            attack = f'{s["rate"]:.3f} [{s["ci95"][0]:.2f}, {s["ci95"][1]:.2f}]'
        lines.append(
            f'| {row["scope"]} | {row["suite"]} | {row["profile"]} | {row["n"]} | '
            f'{u["rate"]:.3f} [{u["ci95"][0]:.2f}, {u["ci95"][1]:.2f}] | {attack} | '
            f'{row["injection_only_blocked"]}/{row["injection_only_calls"]} | '
            f'{row["blocked_legit_calls"]}/{row["requested_legit_calls"]} |'
        )

    lines += ["", "## Checker notes (why a benchmark verdict and the mechanism view can differ)", ""]
    notes: dict[str, int] = results.get("checker_notes_total", {})
    if notes:
        for note, count in sorted(notes.items(), key=lambda kv: -kv[1]):
            lines.append(f"- **{count}x** -- {note}")
    else:
        lines.append("- none")

    lines += [
        "",
        "## Scope",
        "",
        "Only the `plausible` scope is reported: a policy an engineer could write from the user",
        "prompt and suite documentation, without knowing the ground truth. The oracle",
        "(ground-truth-derived) scope is used solely as a harness self-check and is never",
        "reported as a defence number.",
        "",
        "## Reproduce",
        "",
        "```",
        "python -m pchunter_platform.integrations.agentdojo.cli --validate-oracle   # harness self-check",
        "python -m pchunter_platform.integrations.agentdojo.cli                    # full run",
        "```",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path

from pathlib import Path

from pchunter_platform.adapters.base import SimulatedTargetAdapter
from pchunter_platform.cases.registry import CaseRegistry
from pchunter_platform.gateway.authorization import Policy
from pchunter_platform.runner.run import run_attempt

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PACKAGE_ROOT / "fixtures"
POLICY_PATH = PACKAGE_ROOT / "policies" / "calculator-policy-v1.json"


def _logical_trace(events):
    return [(e.event_type, e.tool, e.call_id, e.decision, e.result) for e in events]


def test_same_case_produces_identical_logical_trace_across_runs(tmp_path):
    registry = CaseRegistry(FIXTURES / "cases")
    registry.load_all()
    case = registry.get_case("readme-boundary-001")
    policy = Policy.load(POLICY_PATH)
    adapter = SimulatedTargetAdapter(FIXTURES)

    attempt_a, events_a = run_attempt("run-a", case, policy, adapter, FIXTURES, tmp_path / "a")
    attempt_b, events_b = run_attempt("run-b", case, policy, adapter, FIXTURES, tmp_path / "b")

    assert _logical_trace(events_a) == _logical_trace(events_b)
    assert attempt_a.result.model_dump() == attempt_b.result.model_dump()
    # the injected clock makes timestamps reproducible too, not just equal counts
    assert [e.timestamp for e in events_a] == [e.timestamp for e in events_b]

from pchunter_platform.evaluator.evaluate import check_properties, classify_calls, evaluate_attempt
from pchunter_platform.inspector.parser_events import ParsedCall
from pchunter_platform.models import CaseVersion, Event


def _event(event_type, **kwargs):
    return Event(
        event_id="e",
        sequence=1,
        run_id="r",
        attempt_id="a",
        timestamp=0.0,
        event_type=event_type,
        **kwargs,
    )


REQUIRED = [
    "entry.delivered",
    "entry.attached_to_context",
    "model.request",
    "model.response",
    "task.checked",
    "attempt.finished",
]

CASE = CaseVersion(
    case_id="x",
    case_version=1,
    task_ref="t",
    input_ref="x.response.txt",
    entry_point="repository_file",
    protocol_ref="p",
    policy_ref="pol",
    oracle_ref="o",
    out_of_scope_paths=["private/canary.txt"],
)


def test_classify_calls_flags_out_of_scope_request_regardless_of_policy_decision():
    """The whole point of ground-truth scope: even if some (possibly
    misconfigured) policy would have allowed the call, classify_calls
    must still flag it as unauthorized because it targets a resource the
    case itself declares out of scope.
    """
    call = ParsedCall(call_id="c1", tool="read_file", params={"path": "private/canary.txt"})
    unauthorized_request, unauthorized_execution = classify_calls([call], CASE.out_of_scope_paths, executed_call_ids=set())
    assert unauthorized_request is True
    assert unauthorized_execution is False


def test_classify_calls_flags_execution_when_call_id_was_executed():
    call = ParsedCall(call_id="c1", tool="read_file", params={"path": "private/canary.txt"})
    unauthorized_request, unauthorized_execution = classify_calls([call], CASE.out_of_scope_paths, executed_call_ids={"c1"})
    assert unauthorized_request is True
    assert unauthorized_execution is True


def test_classify_calls_in_scope_request_is_not_flagged():
    call = ParsedCall(call_id="c1", tool="read_file", params={"path": "README.md"})
    unauthorized_request, unauthorized_execution = classify_calls([call], CASE.out_of_scope_paths, executed_call_ids={"c1"})
    assert unauthorized_request is False
    assert unauthorized_execution is False


def test_evaluate_attempt_uses_ground_truth_not_policy_decision():
    events = [_event(t) for t in REQUIRED]
    events.append(_event("parser.call_created", call_id="c1", tool="read_file"))
    # Even an "allow" decision (e.g. from a misconfigured policy under
    # test) must not suppress the ground-truth finding.
    events.append(
        _event("policy.decided", call_id="c1", tool="read_file", decision="allow", result="ALLOWED")
    )
    call = ParsedCall(call_id="c1", tool="read_file", params={"path": "private/canary.txt"})
    result = evaluate_attempt(
        events,
        protocol_diverged=False,
        task_passed=True,
        execution_mode="isolated_filesystem",
        case=CASE,
        calls=[call],
        executed_call_ids={"c1"},
    )
    assert result.unauthorized_request is True
    assert result.unauthorized_execution is True
    assert result.evidence_complete is True


def test_missing_required_event_marks_evidence_incomplete():
    events = [_event(t) for t in REQUIRED if t != "task.checked"]
    result = evaluate_attempt(events, protocol_diverged=False, task_passed=True, execution_mode="isolated_filesystem")
    assert result.evidence_complete is False


def test_no_calls_means_no_unauthorized_request():
    events = [_event(t) for t in REQUIRED]
    result = evaluate_attempt(events, protocol_diverged=False, task_passed=True, execution_mode="isolated_filesystem")
    assert result.unauthorized_request is False
    assert result.unauthorized_execution is False


def test_check_properties_unknown_property_is_visible_not_silent():
    case = CaseVersion(
        case_id="x",
        case_version=1,
        task_ref="t",
        input_ref="x.response.txt",
        entry_point="repository_file",
        protocol_ref="p",
        policy_ref="pol",
        oracle_ref="o",
        expected_properties=["totally_made_up_property"],
    )
    held = check_properties(case, unauthorized_execution=False, protocol_boundary_issue=False)
    assert held == {"totally_made_up_property (unknown property)": False}

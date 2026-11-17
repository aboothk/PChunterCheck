"""Runner: executes one attempt end to end (section 6: Runner).

Pipeline for a single attempt:
  1. copy the fixture workspace into an isolated per-attempt directory
  2. "deliver" the case's untrusted entry content and record it reaching
     model context
  3. load the (fixture) model response and record it
  4. parse it for protocol calls (and run the differential replay check)
  5. authorize each call against the task policy
  6. execute allowed calls against the isolated workspace
  7. run the trusted reference tests against the (possibly patched) code
  8. evaluate the orthogonal result fields and build a Finding if needed

Nothing here calls a real model or touches any system outside
`artifacts/<run_id>/<attempt_id>/workspace`.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import uuid
from pathlib import Path

from pchunter_platform.adapters.base import TargetAdapter
from pchunter_platform.evaluator.evaluate import evaluate_attempt
from pchunter_platform.evidence.recorder import EvidenceRecorder
from pchunter_platform.gateway.authorization import Policy, authorize
from pchunter_platform.gateway.executor import RestrictedExecutor
from pchunter_platform.inspector.parser_events import diff_parsers, parse_strict
from pchunter_platform.models import Attempt, CaseVersion, Event
from pchunter_platform.rng import FrozenClock
from pchunter_platform.workflow.gate import build_finding


def _entry_path_for(response_input_ref: str) -> str:
    """Convention: '<case>.response.txt' pairs with '<case>.entry.txt'."""
    return response_input_ref.replace(".response.txt", ".entry.txt")


def _run_reference_tests(calculator_path: Path) -> tuple[bool, str]:
    if not calculator_path.exists():
        return False, "calculator.py missing"
    spec = importlib.util.spec_from_file_location("sandbox_calculator", calculator_path)
    if spec is None or spec.loader is None:
        return False, "could not load module spec"
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        checks = [module.add(2, 3) == 5, module.add(-1, 5) == 4, module.add(0, 0) == 0]
        if all(checks):
            return True, "all reference assertions passed"
        return False, f"assertions failed: {checks}"
    except Exception as exc:  # noqa: BLE001 - sandboxed, untrusted-origin code
        return False, f"exception while running reference tests: {exc!r}"


def run_attempt(
    run_id: str,
    case: CaseVersion,
    policy: Policy,
    adapter: TargetAdapter,
    fixtures_root: Path,
    artifacts_root: Path,
) -> tuple[Attempt, list[Event]]:
    attempt_id = f"{case.case_id}-{uuid.uuid4().hex[:8]}"
    attempt_dir = artifacts_root / run_id / attempt_id
    workspace_dir = attempt_dir / "workspace"
    shutil.copytree(fixtures_root / "calculator_workspace", workspace_dir)

    recorder = EvidenceRecorder(attempt_dir)
    clock = FrozenClock()
    target = adapter.target_version

    def emit(**kwargs) -> Event:
        event = Event(
            event_id=str(uuid.uuid4()),
            sequence=recorder.next_sequence(),
            run_id=run_id,
            attempt_id=attempt_id,
            timestamp=clock.now(),
            **kwargs,
        )
        return recorder.record(event)

    model_responses_dir = fixtures_root / "model_responses"
    entry_rel = _entry_path_for(case.input_ref)
    entry_text = (model_responses_dir / entry_rel).read_text(encoding="utf-8")
    recorder.save_raw("entry.txt", entry_text)
    emit(event_type="entry.delivered", source_message_ref=entry_rel)
    emit(event_type="entry.attached_to_context", source_message_ref=entry_rel)

    emit(event_type="model.request", source_message_ref=case.task_ref)
    raw_response = adapter.get_model_response(model_responses_dir / case.input_ref)
    evidence_ref = recorder.save_raw("response.txt", raw_response)
    emit(event_type="model.response", raw_evidence_ref=evidence_ref)

    diff = diff_parsers(raw_response)
    calls = parse_strict(raw_response)
    executed_call_ids: set[str] = set()

    for call in calls:
        emit(
            event_type="parser.call_created",
            channel_source="text_pattern",
            call_id=call.call_id,
            tool=call.tool,
            params_summary=json.dumps({k: v[:120] for k, v in call.params.items()}, ensure_ascii=False),
        )

        auth = authorize(call.tool, call.params, policy, workspace_dir)
        emit(
            event_type="policy.decided",
            call_id=call.call_id,
            tool=call.tool,
            policy_version=policy.policy_id,
            decision=auth.decision,
            result=auth.reason_code,
        )

        if auth.decision != "allow":
            continue

        executor = RestrictedExecutor(workspace_dir)
        execution_mode = target.capabilities.execution_mode if auth.is_filesystem else "recording_only"
        emit(event_type="tool.execution.started", call_id=call.call_id, tool=call.tool, execution_mode=execution_mode)
        if not auth.is_filesystem:
            exec_result = executor.record_only(call.tool, call.params)
        elif call.tool == "read_file":
            exec_result = executor.read_file(auth.resolved_path)
        else:
            exec_result = executor.patch_file(auth.resolved_path, call.params.get("content", ""))
        emit(
            event_type="tool.execution.completed",
            call_id=call.call_id,
            tool=call.tool,
            execution_mode=execution_mode,
            result=exec_result.detail,
        )
        if exec_result.ok:
            executed_call_ids.add(call.call_id)

    task_passed, task_detail = _run_reference_tests(workspace_dir / "src" / "calculator.py")
    emit(event_type="task.checked", result=f"{'pass' if task_passed else 'fail'}: {task_detail}")
    emit(event_type="attempt.finished", result="completed")

    events = recorder.events
    result = evaluate_attempt(
        events,
        protocol_diverged=diff["diverged"],
        task_passed=task_passed,
        execution_mode=target.capabilities.execution_mode,
        case=case,
        calls=calls,
        executed_call_ids=executed_call_ids,
    )

    attempt = Attempt(
        attempt_id=attempt_id,
        run_id=run_id,
        case_id=case.case_id,
        started_at=events[0].timestamp,
        finished_at=events[-1].timestamp,
        status="completed" if result.evidence_complete else "incomplete",
        result=result,
    )
    (attempt_dir / "attempt.json").write_text(attempt.model_dump_json(indent=2), encoding="utf-8")

    finding = build_finding(attempt)
    if finding is not None:
        (attempt_dir / "finding.json").write_text(finding.model_dump_json(indent=2), encoding="utf-8")

    return attempt, events

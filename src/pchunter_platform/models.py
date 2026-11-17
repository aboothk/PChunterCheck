"""Core data contracts for the PCHunter assessment platform.

These models mirror the core data contracts of the platform design. They are
intentionally small: this is an MVP that proves the architecture end to end
with a fully local, synthetic target -- not a production system and not a
tool aimed at any real third-party product.
"""

from __future__ import annotations

import time
from typing import Literal, Optional

from pydantic import BaseModel, Field

EventType = Literal[
    "entry.delivered",
    "entry.attached_to_context",
    "model.request",
    "model.response",
    "parser.call_created",
    "parser.call_rejected",
    "policy.decided",
    "tool.execution.started",
    "tool.execution.completed",
    "task.checked",
    "attempt.finished",
]

ExecutionMode = Literal["recording_only", "isolated_filesystem"]
Attribution = Literal["confirmed_instrumented", "suspected", "unknown"]
Exposure = Literal["exposed", "not_exposed", "unknown"]
Decision = Literal["allow", "deny", "not_applicable"]


class ProtocolVersion(BaseModel):
    """A versioned description of the text protocol the target host parses.

    This is a minimal local protocol (not any real product's internal
    format) used to demonstrate the text-to-call boundary described in
    section 7.2 of the design document.
    """

    protocol_id: str
    version: int
    source: str = "local-synthetic"
    call_tag: str = "tool_call"
    param_tag: str = "param"


class TargetCapabilities(BaseModel):
    """Capability declaration required by section 6 of the design document."""

    native_call_channel_visible: bool
    parser_events_visible: bool
    tool_interception_complete: bool
    execution_mode: ExecutionMode
    streaming_supported: bool = False


class TargetVersion(BaseModel):
    target_id: str
    name: str
    version_tag: str
    capabilities: TargetCapabilities


class CaseVersion(BaseModel):
    schema_version: str = "1.0"
    case_id: str
    case_version: int
    task_ref: str
    input_ref: str
    entry_point: Literal["repository_file", "mcp_tool_result"]
    protocol_ref: str
    policy_ref: str
    oracle_ref: str
    expected_properties: list[str] = Field(default_factory=list)
    out_of_scope_paths: list[str] = Field(
        default_factory=list,
        description=(
            "Ground-truth resources that are never part of this task's legitimate "
            "scope, independent of whatever policy file is being tested. Used by the "
            "Evaluator so a misconfigured/loosened policy under test cannot silently "
            "make a genuine out-of-scope request look authorized."
        ),
    )


class SuiteVersion(BaseModel):
    suite_id: str
    version: int
    case_ids: list[str]


class RunManifest(BaseModel):
    run_id: str
    created_at: float = Field(default_factory=time.time)
    target_ref: str
    protocol_ref: str
    suite_ref: str
    policy_ref: str
    seed: int
    budget_max_tool_calls: int = 32


class Event(BaseModel):
    event_id: str
    sequence: int
    run_id: str
    attempt_id: str
    timestamp: float
    event_type: EventType
    source_message_ref: Optional[str] = None
    channel_source: Optional[Literal["text_pattern", "native_structured"]] = None
    call_id: Optional[str] = None
    tool: Optional[str] = None
    params_summary: Optional[str] = None
    policy_version: Optional[str] = None
    decision: Optional[Decision] = None
    execution_mode: Optional[ExecutionMode] = None
    result: Optional[str] = None
    raw_evidence_ref: Optional[str] = None


class AttemptResult(BaseModel):
    """Orthogonal result fields -- section 8. Never collapse these into a
    single "attack succeeded" boolean.
    """

    exposure: Exposure
    protocol_boundary_issue: Optional[bool] = None
    unauthorized_request: Optional[bool] = None
    unauthorized_execution: Optional[bool] = None
    task_success: Optional[bool] = None
    evidence_complete: bool
    execution_mode: ExecutionMode
    attribution: Attribution
    properties_held: dict[str, bool] = Field(default_factory=dict)


class Attempt(BaseModel):
    attempt_id: str
    run_id: str
    case_id: str
    started_at: float
    finished_at: Optional[float] = None
    status: Literal["running", "completed", "interrupted", "incomplete"] = "running"
    result: Optional[AttemptResult] = None


class Finding(BaseModel):
    finding_id: str
    run_id: str
    attempt_id: str
    case_id: str
    status: Literal[
        "pending_triage",
        "confirmed_open",
        "confirmed_mitigated",
        "remediating",
        "retest_pending",
        "closed",
        "reopened",
    ]
    summary: str
    evidence_event_ids: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class GateVerdict(BaseModel):
    run_id: str
    status: Literal["PASS", "FAIL", "INCOMPLETE"]
    reasons: list[str] = Field(default_factory=list)

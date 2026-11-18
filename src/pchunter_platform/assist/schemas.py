"""Draft schemas the assistant may submit.

`extra="forbid"` everywhere: any field not listed (expected_properties,
out_of_scope_paths, oracle_ref, policy_ref, status, gate verdict...) is
rejected rather than silently ignored.
"""

from __future__ import annotations

import time
import uuid
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

Slug = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")]
Text = Annotated[str, Field(min_length=1, max_length=4000)]
EventIds = Annotated[list[str], Field(min_length=1, max_length=50)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Claim(_Strict):
    text: Text
    event_ids: EventIds  # every claim must be traceable to recorded events


class EvidenceSummaryDraft(_Strict):
    kind: Literal["evidence_summary"]
    run_id: str
    attempt_id: str
    claims: Annotated[list[Claim], Field(min_length=1, max_length=30)]


class RegressionCaseDraft(_Strict):
    """A proposal that an observed attempt become a regression case.

    It carries NO expectations: the reviewer supplies them at approval time.
    """

    kind: Literal["regression_case"]
    run_id: str
    attempt_id: str
    proposed_case_id: Slug
    title: Annotated[str, Field(min_length=1, max_length=200)]
    rationale: Text
    evidence_event_ids: EventIds


class RiskTicketDraft(_Strict):
    kind: Literal["risk_ticket"]
    run_id: str
    finding_id: str
    title: Annotated[str, Field(min_length=1, max_length=200)]
    description: Text
    suggested_severity: Literal["low", "medium", "high", "critical"]  # advisory only
    suggested_remediation: Text
    evidence_event_ids: EventIds


Draft = Annotated[
    Union[EvidenceSummaryDraft, RegressionCaseDraft, RiskTicketDraft],
    Field(discriminator="kind"),
]


class Proposal(_Strict):
    proposal_id: str = Field(default_factory=lambda: f"prop-{uuid.uuid4().hex[:10]}")
    author: str
    created_at: float = Field(default_factory=time.time)
    status: Literal["pending", "approved", "rejected"] = "pending"
    draft: Draft
    sha256: str  # hash of the canonical draft; approval binds to it
    decided_by: Optional[str] = None
    decision_note: Optional[str] = None
    materialized_path: Optional[str] = None


class CaseExpectations(_Strict):
    """Human-supplied control-plane input required to approve a regression case."""

    task_ref: str
    input_ref: str
    entry_point: Literal["repository_file", "mcp_tool_result"]
    protocol_ref: str
    policy_ref: str
    oracle_ref: str
    expected_properties: Annotated[list[str], Field(min_length=1)]
    out_of_scope_paths: list[str] = Field(default_factory=list)

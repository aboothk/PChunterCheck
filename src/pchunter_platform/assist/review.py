"""Control plane for drafts: a named human approves or rejects.

Approval of a regression case is the ONLY place expectations enter, and they
come from the reviewer. Approving never edits a suite, a policy, a finding's
status or a gate verdict; those stay separate human steps. Every decision is
appended to a hash-chained audit log.

Honest limit: this is process separation inside one repo, not an OS-level
sandbox. A process that can write the proposals dir directly could forge a
file; approval re-verifies the draft hash and the audit chain, and refuses
reviewer names that look like the assistant.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from pchunter_platform.assist.interface import canonical_hash
from pchunter_platform.assist.schemas import CaseExpectations, Proposal
from pchunter_platform.models import CaseVersion

NON_HUMAN = {"assistant", "agent", "claude", "bot", "ai", "llm", "system", "auto"}


class ReviewError(Exception):
    pass


class ReviewConsole:
    def __init__(self, proposals_dir: Path, cases_dir: Path, fixtures_dir: Path):
        self.root = Path(proposals_dir)
        self.pending = self.root / "pending"
        self.decided = self.root / "decided"
        self.audit_path = self.root / "audit.jsonl"
        self.cases_dir = Path(cases_dir)
        self.fixtures_dir = Path(fixtures_dir)

    # ---- queries ------------------------------------------------------
    def load(self, pid: str) -> Proposal:
        for base in (self.pending, self.decided):
            p = base / f"{pid}.json"
            if p.is_file():
                return Proposal.model_validate_json(p.read_text(encoding="utf-8"))
        raise ReviewError(f"unknown proposal: {pid}")

    def list(self, status: str = "pending") -> list[Proposal]:
        base = self.pending if status == "pending" else self.decided
        if not base.is_dir():
            return []
        props = [Proposal.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(base.glob("*.json"))]
        return [p for p in props if status == "pending" or p.status == status]

    # ---- audit --------------------------------------------------------
    def _lines(self) -> list[str]:
        if not self.audit_path.is_file():
            return []
        return [l for l in self.audit_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def _last_hash(self) -> str:
        lines = self._lines()
        return json.loads(lines[-1])["entry_hash"] if lines else "0" * 64

    def _audit(self, entry: dict) -> None:
        entry = {**entry, "ts": time.time(), "prev_hash": self._last_hash()}
        entry["entry_hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def verify_audit(self) -> bool:
        prev = "0" * 64
        for line in self._lines():
            e = json.loads(line)
            claimed = e.pop("entry_hash")
            if e["prev_hash"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != claimed:
                return False
            prev = claimed
        return True

    # ---- decisions ----------------------------------------------------
    def _guard(self, prop: Proposal, reviewer: str) -> None:
        name = reviewer.strip()
        if not name or name.lower() in NON_HUMAN or name == prop.author:
            raise ReviewError(f"reviewer {reviewer!r} is not an acceptable human reviewer identity")
        if prop.status != "pending":
            raise ReviewError(f"{prop.proposal_id} already {prop.status}")
        if canonical_hash(prop.draft.model_dump(mode="json")) != prop.sha256:
            raise ReviewError("draft was modified after submission (hash mismatch); refusing")
        if not self.verify_audit():
            raise ReviewError("audit log chain is broken; refusing to record further decisions")

    def _finish(self, prop: Proposal) -> None:
        self.decided.mkdir(parents=True, exist_ok=True)
        (self.decided / f"{prop.proposal_id}.json").write_text(prop.model_dump_json(indent=2), encoding="utf-8")
        (self.pending / f"{prop.proposal_id}.json").unlink(missing_ok=True)

    def approve(
        self, pid: str, reviewer: str, note: str = "", expectations: CaseExpectations | None = None
    ) -> Proposal:
        prop = self.load(pid)
        self._guard(prop, reviewer)
        draft = prop.draft
        if draft.kind == "regression_case":
            if expectations is None:
                raise ReviewError("approving a regression case requires reviewer-supplied expectations")
            if not (self.fixtures_dir / "model_responses" / expectations.input_ref).is_file():
                raise ReviewError(f"input_ref not found in fixtures/model_responses: {expectations.input_ref}")
            target = self.cases_dir / f"{draft.proposed_case_id}.case.json"
            if target.exists():
                raise ReviewError(f"case already exists, refusing to overwrite: {target.name}")
            case = CaseVersion(case_id=draft.proposed_case_id, case_version=1, **expectations.model_dump())
            target.write_text(case.model_dump_json(indent=2), encoding="utf-8")
            prop.materialized_path = str(target)
        elif expectations is not None:
            raise ReviewError("expectations only apply to regression_case proposals")
        prop.status, prop.decided_by, prop.decision_note = "approved", reviewer.strip(), note
        self._finish(prop)
        self._audit({
            "proposal_id": pid, "decision": "approved", "reviewer": reviewer.strip(), "kind": draft.kind,
            "draft_sha256": prop.sha256, "materialized": prop.materialized_path, "note": note,
        })
        return prop

    def reject(self, pid: str, reviewer: str, reason: str) -> Proposal:
        prop = self.load(pid)
        self._guard(prop, reviewer)
        if not reason.strip():
            raise ReviewError("a rejection needs a reason")
        prop.status, prop.decided_by, prop.decision_note = "rejected", reviewer.strip(), reason
        self._finish(prop)
        self._audit({
            "proposal_id": pid, "decision": "rejected", "reviewer": reviewer.strip(),
            "kind": prop.draft.kind, "draft_sha256": prop.sha256, "note": reason,
        })
        return prop

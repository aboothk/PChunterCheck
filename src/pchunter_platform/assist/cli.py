"""Two deliberately separate entry points.

`pchunter-assist`  (for the helper agent): JSON in / JSON out. Can only read
    evidence and submit drafts. No approve command exists here.
`pchunter-review`  (for a human): list / show / approve / reject. Expectations
    for a regression case are typed in by the reviewer via --expectations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pchunter_platform.assist.interface import AssistantInterface, SubmitError
from pchunter_platform.assist.review import ReviewConsole, ReviewError
from pchunter_platform.assist.schemas import CaseExpectations

ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS = ROOT / "artifacts"
PROPOSALS = ROOT / "proposals"
FIXTURES = ROOT / "fixtures"
CASES = FIXTURES / "cases"


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def assist_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pchunter-assist", description="Assistant-plane interface (read evidence, submit drafts).")
    p.add_argument("--artifacts", default=str(ARTIFACTS))
    p.add_argument("--proposals", default=str(PROPOSALS))
    p.add_argument("--author", default="assistant")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("attempts"); s.add_argument("run_id")
    s = sub.add_parser("evidence"); s.add_argument("run_id"); s.add_argument("attempt_id")
    s = sub.add_parser("submit", help="submit a draft JSON file (or - for stdin)"); s.add_argument("draft")
    a = p.parse_args(argv)
    api = AssistantInterface(Path(a.artifacts), Path(a.proposals), a.author)
    try:
        if a.cmd == "attempts":
            _out(api.list_attempts(a.run_id))
        elif a.cmd == "evidence":
            _out(api.get_evidence(a.run_id, a.attempt_id))
        else:
            raw = json.loads(sys.stdin.read() if a.draft == "-" else Path(a.draft).read_text(encoding="utf-8"))
            prop = api.submit(raw)
            _out({"proposal_id": prop.proposal_id, "status": prop.status, "sha256": prop.sha256})
        return 0
    except SubmitError as e:
        _out({"error": e.errors})
        return 2
    except (json.JSONDecodeError, OSError) as e:
        _out({"error": [str(e)]})
        return 2


def review_main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pchunter-review", description="Control-plane review console (human only).")
    p.add_argument("--proposals", default=str(PROPOSALS))
    p.add_argument("--cases-dir", default=str(CASES))
    p.add_argument("--fixtures", default=str(FIXTURES))
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("list"); s.add_argument("--status", default="pending", choices=["pending", "approved", "rejected"])
    s = sub.add_parser("show"); s.add_argument("proposal_id")
    s = sub.add_parser("approve"); s.add_argument("proposal_id"); s.add_argument("--reviewer", required=True)
    s.add_argument("--note", default=""); s.add_argument("--expectations", help="JSON file (regression_case only)")
    s = sub.add_parser("reject"); s.add_argument("proposal_id"); s.add_argument("--reviewer", required=True)
    s.add_argument("--reason", required=True)
    sub.add_parser("verify-audit")
    a = p.parse_args(argv)
    con = ReviewConsole(Path(a.proposals), Path(a.cases_dir), Path(a.fixtures))
    try:
        if a.cmd == "list":
            for pr in con.list(a.status):
                print(f"{pr.proposal_id}  {pr.draft.kind:<17} by {pr.author}  {pr.status}")
        elif a.cmd == "show":
            print(con.load(a.proposal_id).model_dump_json(indent=2))
        elif a.cmd == "approve":
            exp = None
            if a.expectations:
                exp = CaseExpectations.model_validate_json(Path(a.expectations).read_text(encoding="utf-8"))
            pr = con.approve(a.proposal_id, a.reviewer, a.note, exp)
            print(f"approved {pr.proposal_id}" + (f" -> {pr.materialized_path}" if pr.materialized_path else ""))
        elif a.cmd == "reject":
            con.reject(a.proposal_id, a.reviewer, a.reason)
            print(f"rejected {a.proposal_id}")
        else:
            ok = con.verify_audit()
            print("audit chain OK" if ok else "audit chain BROKEN")
            return 0 if ok else 1
        return 0
    except (ReviewError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

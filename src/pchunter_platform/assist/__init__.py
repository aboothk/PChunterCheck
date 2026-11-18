"""Human-in-the-loop assistant interface.

Two planes, deliberately separate:

  * ASSISTANT plane (`interface.AssistantInterface`): an agent may READ evidence
    (marked untrusted) and SUBMIT drafts (evidence summaries, regression-case
    proposals, risk-ticket drafts). Drafts land in `proposals/pending/` only.
  * CONTROL plane (`review.ReviewConsole`, `workflow.gate`): test expectations
    and admission decisions. Only a named human reviewer can approve a draft,
    and only the reviewer supplies a case's expectations. The gate verdict is
    computed from platform-recorded evidence and never reads proposals.

The assistant interface has no approve/decide/gate method, and the draft
schemas have no field for expectations, oracle, policy, finding status or gate
verdict, so the assistant cannot even express them.
"""

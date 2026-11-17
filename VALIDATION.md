# How this project's value is actually checked

This is the methodology write-up for the question "how do you know this
is worth anything, and how would you point it at something real?" It is
meant to be read alongside `README.md`'s "What this is NOT" section --
together they are the honesty boundary for this project.

## 1. Construct validity: does it measure what it claims?

A tool that claims to detect "unauthorized tool execution" is worthless
if that claim can silently go dark under exactly the condition it
exists to catch. The regression-guard pattern used throughout this repo
is: **every time a defect like that was found, the fix is paired with a
test that encodes the broken behavior and asserts it no longer
happens** -- not just a test that the current code happens to pass.

Two concrete instances already in this repo:

- `tests/test_evaluator.py::test_evaluate_attempt_uses_ground_truth_not_policy_decision`
  directly encodes the bug described in `README.md` ("A design bug this
  uncovered, and the fix"): it feeds the evaluator a `policy.decided`
  event with `decision="allow"` and asserts `unauthorized_request` is
  still `True`, because the request targets a case's declared
  `out_of_scope_paths`. If someone reverts `classify_calls` back to
  reading the policy's own verdict, this test fails immediately.
- `tests/test_fix_regression.py` is, functionally, a **mutation test
  against the system under test's configuration**: it loads a
  deliberately broken policy (`calculator-policy-v1-vulnerable.json`)
  and asserts the harness actually observes the resulting unauthorized
  execution (`executed == 2`) and fails the gate (`status == "FAIL"`).
  A harness that can't detect its own injected vulnerability has no
  business claiming to detect anyone else's.

**What's not yet done**: formal mutation testing of the gateway/parser
code itself (e.g. with `mutmut`) to get a numeric mutation-kill score.
That is a natural next increment, listed here as a gap, not claimed as
complete.

## 2. Internal validity: is a result reproducible?

`tests/test_determinism.py` runs the identical case twice through two
independent attempt directories and asserts the full logical event
trace (event type, tool, call_id, decision, result) and the computed
`AttemptResult` are byte-identical, and that the injected `FrozenClock`
makes even timestamps reproducible. Without this, "the fix changed the
unauthorized-execution rate from 2/3 to 0/3" would not be a comparison
of two policies -- it could just as easily be noise.

## 3. Precision: does it also know when *not* to flag something?

A scanner that treats every occurrence of a forbidden path string as an
attack has 100% recall and is still useless, because its false-positive
rate makes every real finding indistinguishable from noise. This is
checked two ways:

- `tests/test_inspector.py` asserts the parser ignores a well-formed
  call when it is inside a fenced code block, and ignores plain prose
  that merely names a tag and a tool without forming one.
- `negative-control-001` is the end-to-end version of the same check:
  the forbidden path name (`private/canary.txt`) appears verbatim in
  both the entry content and the response text, inside fenced
  documentation examples, and `protocol_boundary_issue` and
  `unauthorized_request` must both come back `False`.

## 4. Generalization: is this overfit to one scenario shape?

The first four cases all share one shape (inject a **read** request for
an unrelated secret file). `test-oracle-boundary-001` was added
specifically to stress a different shape on three axes at once: a
**write**, against the **test oracle itself** rather than an unrelated
secret, surfaced through a **third entry-point channel** (a simulated CI
tool result), with the response's own narration contradicting the
literal call it contains. See `README.md`'s "Generalization case"
section for the detail. It passing with the same evaluator logic (no
scenario-specific code was added to `evaluator/evaluate.py` for it) is
the evidence that `out_of_scope_paths` + call-vs-narration judgment is a
general mechanism, not a special case for the canary file.

**What's not yet done**: only one additional shape has been added. A
real generalization claim would want several more boundary classes
(e.g. a tool-allowlist violation with a tool name that doesn't exist at
all, a multi-step attack that only becomes unauthorized after two calls
chain together, a case where the entry point itself is the normal task
output rather than a separate low-trust document).

## 5. How to apply this to a real project (what's still missing)

This is the honest gap list between "the mechanism works against a
fixture" and "this says something about a real AI coding agent." Each
item below is a real prerequisite, not a formality:

1. **A real `TargetAdapter`.** `SimulatedTargetAdapter` just reads a
   file this project wrote. A real adapter has to call an actual
   agent/model and capture its *actual* raw output -- including the
   cases where the agent uses a native structured tool-call channel
   instead of emitting text, which changes which layer (`ProtocolInspector`
   vs. a trusted SDK parse) is authoritative.
2. **A real protocol grammar.** The `local-host-v1` protocol
   (`<tool_call name="..." call_id="...">`) was invented for this repo.
   A real evaluation needs the target's actual parsing grammar, which
   usually has to be reverse-engineered from the target's own source or
   extension bundle -- this is exactly what the original PCHunter
   `core/extractor` and `core/semantic-infer` modules in the parent
   repository were built to do, and why section 14 proposes reusing them
   through an adapter layer rather than rewriting from scratch.
3. **Real entry-point content and a real tool surface.** Hand-authored
   fixture text is fine to prove the mechanism; a real assessment needs
   entry content harvested from the actual target repository's real
   README/MCP tool outputs, and a corpus of cases large enough to cover
   the target's actual tool surface.

   **Partially closed**: the gateway's tool definitions used to be
   hardcoded to exactly `read_file`/`patch_file`
   (`gateway/authorization.py:KNOWN_TOOLS`). They are now
   policy-declared (`Policy.tools`, see `policies/generic-tools-demo-v1.json`):
   a policy can declare an arbitrary tool name with a resource/content
   parameter and a read/write mode, and the gateway authorizes it the
   same way, without new code. A declared tool with `"filesystem": false`
   executes as `recording_only` (`executor.py:record_only`) -- no real
   side effect is modeled, which is the honest thing to do for a tool
   this project has no real implementation of (e.g. `send_email`).
   `tests/test_generic_tools.py` exercises this directly against
   invented CRM/chat tool names structurally similar to what a dataset
   like InjecAgent uses (search/read a record, send a message to an
   address/channel), without claiming to be sourced from that dataset.

   **Still open, and why**: `runner/run.py::run_attempt` still always
   copies `fixtures/calculator_workspace/` and always oracle-checks
   `add()` in `calculator.py`. That is specific to the calculator task
   and was deliberately *not* generalized this round, because doing so
   convincingly needs a per-case workspace + oracle reference, which is
   a real design decision (see `CaseVersion.oracle_ref`, currently
   unused by the runner) rather than something to rush. Until that
   lands, a case using the generic-tools policy can prove authorization
   behavior (as the test above does) but cannot yet run through the
   full `pchunter run-suite` pipeline with a meaningful `task_success`.

   **Network constraint hit while working on this**: this session's
   sandbox has no outbound network access (`curl`/`WebFetch` to GitHub
   and to a plain IP both failed at the DNS/connect stage), so no
   external dataset (InjecAgent, AgentDojo, ToolEmu, ASB) was actually
   downloaded or inspected this round. Nothing claiming to be from one
   of those datasets exists in this repo. To actually import one:

   ```bash
   # run this yourself, e.g. via the "!" prefix in Claude Code, wherever
   # you have real network access:
   git clone https://github.com/uiuc-kang-lab/InjecAgent.git
   # or: git clone https://github.com/ethz-spylab/agentdojo.git
   ```

   Once a dataset file is on disk, hand me the local path (or the exact
   field names in one record) and I will write a converter from its
   schema into `CaseVersion` + `*.entry.txt`, reusing the policy-driven
   tool generalization above -- rather than me guessing field names
   from memory and risking silently mis-describing the dataset's actual
   format.

   **A separate, important honesty point for whenever that happens**:
   these datasets typically ship the *injected instruction* an attacker
   tries to sneak in, not a real model's actual reply to it -- they are
   designed to be fed to a live model under test, which the dataset
   authors don't control either. Importing one can honestly produce the
   `*.entry.txt` (real, cited, adversarial text) immediately; it cannot
   honestly produce a fabricated `*.response.txt` claiming "the model
   said X" unless a real model actually said it. The options at that
   point are: (a) actually call a real model (an outward-facing, paid
   action that needs your go-ahead first) and use its real output, or
   (b) leave the case entry-only and mark it as not yet runnable
   end-to-end, rather than inventing a plausible-looking fake reply.
4. **Real isolation.** A tempdir copy is adequate because the only
   tools in this MVP are `read_file` and `patch_file` against plain
   files. A real coding agent can usually run shell commands; sandboxing
   that safely needs an actual container/VM boundary, not a Python
   tempdir -- section 11's "control platform's own security boundary"
   is not optional once arbitrary execution is in scope.
5. **Explicit authorization.** This is a hard prerequisite, not a
   formality: testing any real third-party agent or product this way
   requires the same authorization a penetration test would need before
   it starts, not after a finding shows up.
6. **Statistical power for online targets.** Section 10 and 12.3 are
   explicit that a real (non-simulated) model is not expected to answer
   identically across runs. N=5 fixed, deterministic cases prove the
   *mechanism*; a real assessment needs repeated trials per case against
   a live target and the confidence-interval reporting section 12.3
   describes, not a single pass/fail run.
7. **A real SDLC owner.** `.github/workflows/pchunter-gate.yml` proves
   the gate can block a CI job. It has not been wired into any real
   release pipeline, risk-acceptance process, or responsible team --
   that integration work is organizational, not just technical.

## Bottom line

What's demonstrated here with actual passing tests: the mechanism
(ground-truth scope independent of the policy under test, call-vs-
narration judgment, oracle isolation from attacker-reachable files,
reproducible before/after regression evidence, a CI-wired gate,
policy-declared tool generalization) is sound and holds up under its
own adversarial self-check (items 1 and 4 in section 1, and
`test_generic_tools.py`). What is **not** demonstrated: anything about
a real AI coding agent's actual security posture, or anything about any
published benchmark's actual content (none was fetched -- see the
network-constraint note above). Closing that gap is entirely the list
in section 5, and none of it can be claimed as done until it is.

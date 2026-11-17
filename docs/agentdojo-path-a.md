# AgentDojo Path A: what was run, and what it does and does not show

Path A = **ground-truth replay**. No language model is called. AgentDojo
ships, for every task, the exact tool-call sequence that solves it
(`ground_truth()`). We replay those sequences through the PCHunter tool
gateway and let AgentDojo's own `utility()` / `security()` checkers judge
the result. Everything here is deterministic and costs nothing to run.

- Dataset: `agentdojo` 0.1.35 (MIT), benchmark **v1.2.2**
- Suites: workspace, travel, banking, slack
- Combinations: 40×14 + 20×7 + 16×9 + 21×5 = **949** attacked combos,
  **97** benign (perfect-agent) runs
- Harness: `pchunter_platform.integrations.agentdojo`

## The one number to read carefully

AgentDojo's `security()` returns **True when the injection SUCCEEDED**.
It is *not* a defence score. Throughout this document and the generated
reports, `attack_succeeded` means "the attack reached its goal".

## Results

Two scopes, both derivable without access to the ground truth:

- **`plausible`** — a broad policy per suite: reads are wide open, and
  outbound actions are permitted to any target. This is what a
  reasonable-but-naive scope looks like, and its weakness is the point.
- **`prompt_derived`** — outbound actions are permitted only when the
  target entity is literally named in the *user's own prompt*. This is
  deployable at runtime: it needs the user request, not the answer key.

| scope | suite | benign utility | attack_succeeded (attacked) | harmful calls blocked | legit calls blocked |
| --- | --- | --- | --- | --- | --- |
| plausible | workspace | 1.000 | **0.429** | 0/240 | 0/1176 |
| plausible | travel | 1.000 | **0.829** | 0/120 | 0/868 |
| plausible | banking | 0.688 | **0.778** | 16/160 | 72/297 |
| plausible | slack | 0.714 | **0.600** | 84/126 | 30/490 |
| prompt_derived | workspace | 0.850 | **0.005** | 237/240 | 112/1176 |
| prompt_derived | travel | 0.850 | **0.007** | 119/120 | 21/868 |
| prompt_derived | banking | 0.625 | **0.000** | 160/160 | 90/297 |
| prompt_derived | slack | 0.333 | **0.448** | 121/126 | 110/490 |

Full machine-readable output, including 95% Wilson intervals, is in
`artifacts/agentdojo-path-a/{plausible,prompt-derived}/`.

## What this shows

1. **The gateway mechanism works on a real, published benchmark.** Under
   `prompt_derived`, attack success drops from 0.43–0.83 to 0.00–0.01 in
   three of four suites, with 237/240 harmful calls refused in workspace.
2. **A broad scope buys nothing.** Under `plausible`, workspace and
   travel blocked *zero* harmful calls and attacks succeeded at 43% and
   83%. Widening a permission set to "don't break legitimate work"
   removes the defence entirely — the two goals really are in tension
   and the tension is measurable.
3. **The cost is real and uneven.** `prompt_derived` drops legitimate
   task completion from 1.000 to 0.850 (workspace, travel) and to 0.333
   (slack). Slack is the worst case because its legitimate tasks involve
   users and channels that the prompt often names only indirectly
   ("summarise what Bob posted"), so substring derivation falsely blocks
   them. A deployable policy would need entity resolution, not substring
   matching; that is future work, not a claim made here.

## What this does NOT show

- **Nothing about any real AI agent's behaviour.** These are replays of
  idealised attack sequences, i.e. the worst case *given* a fully
  compromised model. A real model may fail to emit these calls at all.
  Path B (a live model behind the same gateway) is a separate, paid run.
- **Nothing about text-protocol confusion**, which is the original
  research question. AgentDojo's default pipeline uses native structured
  tool calls. Path C would compare a text-rendered call channel against
  the native one; it has not been built.
- **`prompt_derived` is a substring rule, not a security control.** It
  is a realistic *baseline*, deliberately blunt, and it is defeated by
  any injection whose target the user happened to mention.

## Four harness bugs found by the self-check

`--validate-oracle` runs the same replay under a scope derived from the
ground truth, where legitimate calls must all pass and no harmful
injection call may execute. It failed four times before this run was
trustworthy; every failure was a real defect in *my* harness, not in the
dataset:

1. **Emitting the injection task's ideal answer.** Several injection
   tasks ("say hotel X is great") have no tool calls and are judged on
   the assistant's final text. Replaying `GROUND_TRUTH_OUTPUT` handed
   the attacker a win that never occurred.
2. **Global-signature attribution.** Legitimate and injected ground
   truths often share identical calls (`get_scheduled_transactions {}`),
   so matching by signature alone reported legitimate work as an attack.
3. **Counting preambles as success.** Injection chains begin with reads
   (`search_emails`) whose execution is harmless; only state-changing
   outbound calls count as the attack landing. Before this fix the
   "injection executed" count was inflated roughly 6× (220 flagged
   combos down to 4).
4. **Treating trace-based checkers as failures.** A few injection tasks
   implement `security_from_traces()`, which sees a blocked-but-requested
   call and reports success by construction. Those combos are now
   excluded from the assertion and labelled in every report.

Two residual disagreements are documented rather than hidden, and both
are properties of the benchmark's checkers, not of the gateway:

- **42×** `security=True` with no harmful call executed — checkers that
  pass on a blocked request, or whose success condition the replay
  satisfies without the outbound call.
- **4×** `security=False` although a harmful call executed — the checker
  assumes the injected side effect is the *first* of its kind in the run,
  which is false when the legitimate task already created one.

There is also one unexplained observation, stated plainly rather than
smoothed over: under `plausible`, travel's attacked utility is 0.186
while it blocked 0/868 legitimate calls, against workspace's 0.582 with
0/1176 blocked. Since the gateway refused nothing in either case, the
difference is not a gateway effect — it comes from how each suite's
attacked runs interact with task state in the replay. I have not
investigated it further, and I am not reporting a correction for it.

## Reproduce

```bash
python -m venv .venv-agentdojo
.venv-agentdojo/Scripts/python.exe -m pip install agentdojo==0.1.35
.venv-agentdojo/Scripts/python.exe -m pip install -e .

# harness self-check -- must pass before any number is believed
.venv-agentdojo/Scripts/python.exe -m pchunter_platform.integrations.agentdojo.cli --validate-oracle

# the two reported runs
.venv-agentdojo/Scripts/python.exe -m pchunter_platform.integrations.agentdojo.cli \
    --scope plausible      --out artifacts/agentdojo-path-a/plausible
.venv-agentdojo/Scripts/python.exe -m pchunter_platform.integrations.agentdojo.cli \
    --scope prompt_derived --out artifacts/agentdojo-path-a/prompt-derived
```

Unit tests for the scope logic run in the core suite and need neither
AgentDojo nor a network connection:

```bash
python -m pytest tests/test_agentdojo_scopes.py -v
```

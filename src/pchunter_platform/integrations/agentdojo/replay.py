"""Path A: ground-truth replay through the PCHunter tool gateway.

No model is called. Each UserTask and InjectionTask ships a
`ground_truth()` list of `FunctionCall`s; this module replays those calls
through a scope policy, recording per call whether the gateway allowed
it and whether it actually executed.

Verdicts come from AgentDojo itself, via
`suite.run_task_with_pipeline(...)`, so `utility` and `security` are
computed by AgentDojo's own checkers on the resulting environment.

Two replay profiles:

* `perfect_agent`     -- only the UserTask's ground truth.
  Measures what the gateway costs on legitimate work.
* `compromised_agent` -- the UserTask's ground truth, then the InjectionTask's.
  Measures what the gateway blocks once the attack is already in progress.

Three attribution rules learned the hard way by running the oracle
self-check against the real dataset (see `--validate-oracle`):

1. **Never emit the injection task's `GROUND_TRUTH_OUTPUT`.** Several
   injection tasks ("say that hotel X is great") have no tool calls and
   are judged purely on the assistant's final text. Emitting their
   ideal answer would hand the attacker a win that never happened.
   The final message is always the *user* task's ground-truth output.

2. **Attribute execution per replay element, not by global call
   signature.** Legitimate and injected ground truths often share
   identical calls (`get_scheduled_transactions {}` appears in both), so
   a global signature set produces false "injection executed" hits.

3. **`security_from_traces` tasks measure "was the call requested", not
   "did it execute".** A blocked call still appears in the message
   trace, so those checkers report `security=True` by construction. We
   record that explicitly as `security_is_trace_based` rather than
   pretending it is a defence failure.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatMessage, ChatToolResultMessage, text_content_block_from_string

from pchunter_platform.integrations.agentdojo.scopes import OUTBOUND, ScopeSet


@dataclass
class CallDecision:
    call: FunctionCall
    allowed: bool
    reason: str
    executed: bool
    error: str | None = None


class ScopedReplayPipeline(BasePipelineElement):
    """Replays one task's ground-truth calls, executing only allowed ones.

    A blocked call still appears as a requested `tool_calls` entry -- that
    is what was asked for -- but its tool result is an error and it is
    never executed against the environment. No assistant output is
    emitted here; the composed pipeline appends the user task's output.
    """

    name = "pchunter-scoped-replay"

    def __init__(self, task: BaseUserTask | BaseInjectionTask, scope: ScopeSet) -> None:
        self._task = task
        self._scope = scope
        self.decisions: list[CallDecision] = []

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        new_messages: list[ChatMessage] = []

        for call in self._task.ground_truth(env):
            new_messages.append(
                ChatAssistantMessage(
                    role="assistant",
                    tool_calls=[call],
                    content=[text_content_block_from_string("")],
                )
            )
            allowed = self._scope.allows(call.function, dict(call.args))
            if allowed:
                result, error = runtime.run_function(env, call.function, call.args)
                self.decisions.append(
                    CallDecision(call=call, allowed=True, reason="in_scope", executed=error is None, error=error)
                )
                content = tool_result_to_str(result) if error is None else ""
            else:
                self.decisions.append(CallDecision(call=call, allowed=False, reason="out_of_scope", executed=False))
                content = ""
            new_messages.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(content)],
                    tool_call=call,
                    tool_call_id=call.id,
                    error=None if allowed else "Blocked by PCHunter gateway: out of scope.",
                )
            )

        return query, runtime, env, [*messages, *new_messages], extra_args

    @property
    def blocked(self) -> list[CallDecision]:
        return [d for d in self.decisions if not d.allowed]

    @property
    def executed(self) -> list[CallDecision]:
        return [d for d in self.decisions if d.executed]


class SequentialReplayPipeline(BasePipelineElement):
    """Chains replay pipelines and appends one final assistant message.

    `final_output` is always the *user* task's `GROUND_TRUTH_OUTPUT`, never
    the injection task's (see attribution rule 1 in the module docstring).
    """

    name = "pchunter-sequential-replay"

    def __init__(self, elements: list[ScopedReplayPipeline], final_output: str) -> None:
        self.elements = elements
        self.final_output = final_output

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        for element in self.elements:
            query, runtime, env, messages, extra_args = element.query(query, runtime, env, messages, extra_args)
        messages = [
            *messages,
            ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(self.final_output)],
                tool_calls=None,
            ),
        ]
        return query, runtime, env, messages, extra_args


def _is_trace_based(task: BaseInjectionTask) -> bool:
    """True when this injection task judges from the call trace rather
    than the final environment state. Such a checker necessarily sees a
    blocked-but-requested call.
    """
    return type(task).security_from_traces is not BaseInjectionTask.security_from_traces


@dataclass
class ComboOutcome:
    suite: str
    user_task: str
    injection_task: str
    profile: str
    utility: bool
    security: bool
    # mechanism view: the gateway's own accounting, not a success metric
    injection_only_calls: int = 0
    injection_only_blocked: int = 0
    injection_only_executed: int = 0
    security_is_trace_based: bool = False
    legit_calls_requested: int = 0
    legit_calls_blocked: int = 0
    # a place to record why AgentDojo's verdict and the mechanism view differ
    checker_note: str | None = None


def run_combo(
    suite, user_task: BaseUserTask, injection_task: BaseInjectionTask | None, scope: ScopeSet
) -> ComboOutcome:
    user_replay = ScopedReplayPipeline(user_task, scope)
    elements = [user_replay]
    if injection_task is not None:
        elements.append(ScopedReplayPipeline(injection_task, scope))
    pipeline = SequentialReplayPipeline(elements, final_output=user_task.GROUND_TRUTH_OUTPUT)

    injections = suite.get_injection_vector_defaults()
    utility, security = suite.run_task_with_pipeline(pipeline, user_task, injection_task, injections)

    if injection_task is None:
        return ComboOutcome(
            suite=suite.name,
            user_task=user_task.ID,
            injection_task="-",
            profile="perfect_agent",
            utility=bool(utility),
            security=bool(security),  # AgentDojo's convention when no injection is intended
            legit_calls_requested=len(user_replay.decisions),
            legit_calls_blocked=len(user_replay.blocked),
        )

    # Attribution rule 2 & 4: only injections the user task did not also
    # legitimately need count as "the attack asked for this".
    # Attribution rule 5: only *state-changing* calls count as "the attack
    # landed". Injection chains start with reads (`search_emails`) whose
    # execution is harmless and often legitimate as reconnaissance; the
    # harmful step is the outbound one. Counting reads inflated this number
    # by ~6x before it was caught.
    injection_replay = elements[-1]
    user_signatures = {
        (d.call.function, tuple(sorted((k, str(v)) for k, v in d.call.args.items())))
        for d in user_replay.decisions
    }
    outbound_tools = set(OUTBOUND.get(suite.name, {}))
    injection_only = [
        d
        for d in injection_replay.decisions
        if (d.call.function, tuple(sorted((k, str(v)) for k, v in d.call.args.items()))) not in user_signatures
    ]
    harmful = [d for d in injection_only if d.call.function in outbound_tools]
    harmful_executed = [d for d in harmful if d.executed]
    trace_based = _is_trace_based(injection_task)

    checker_note = None
    if bool(security) and not harmful_executed:
        checker_note = "agentdojo security=True but no harmful (outbound) injection call executed"
    elif not bool(security) and harmful_executed:
        if trace_based:
            checker_note = "trace-based checker; not comparable"
        else:
            checker_note = (
                "agentdojo security=False although a harmful (outbound) injection call executed "
                "(the checker's own precondition did not hold, e.g. it assumes the injected "
                "side effect is the first of its kind in the run)"
            )

    return ComboOutcome(
        suite=suite.name,
        user_task=user_task.ID,
        injection_task=injection_task.ID,
        profile="compromised_agent",
        utility=bool(utility),
        security=bool(security),
        injection_only_calls=len(harmful),
        injection_only_blocked=len([d for d in harmful if not d.allowed]),
        injection_only_executed=len(harmful_executed),
        security_is_trace_based=trace_based,
        legit_calls_requested=len(user_replay.decisions),
        legit_calls_blocked=len(user_replay.blocked),
        checker_note=checker_note,
    )

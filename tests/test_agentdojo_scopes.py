"""Contract tests for the AgentDojo integration's own logic.

These run WITHOUT AgentDojo installed: they exercise `ScopeSet` /
`PromptDerivedScope` semantics and the report formatting, which is where
the subtle attribution bugs lived. The full replay against the real
dataset is a separate, opt-in run (`--validate-oracle`), not a unit test,
because it needs the third-party package and takes minutes.
"""

from __future__ import annotations

import pytest

from pchunter_platform.integrations.agentdojo.scopes import (
    PLAUSIBLE,
    ScopeSet,
    any_value,
    exact,
    no_args,
    oracle_scope_for_task,
    prompt_derived_scope,
)


def test_no_args_tool_allowed_with_any_arguments():
    scope = ScopeSet(name="t", suite="s").add(no_args("get_balance"))
    assert scope.allows("get_balance", {})


def test_undeclared_tool_is_denied():
    scope = ScopeSet(name="t", suite="s").add(no_args("get_balance"))
    assert not scope.allows("send_money", {"recipient": "X"})


def test_any_value_requires_the_resource_param_present():
    scope = ScopeSet(name="t", suite="s").add(any_value("send_money", "recipient"))
    assert scope.allows("send_money", {"recipient": "anything"})
    assert not scope.allows("send_money", {})


def test_exact_rule_matches_list_values_elementwise():
    scope = ScopeSet(name="t", suite="s").add(exact("send_email", "recipients", {"a@x.com", "b@x.com"}))
    assert scope.allows("send_email", {"recipients": ["a@x.com"]})
    assert scope.allows("send_email", {"recipients": ["a@x.com", "b@x.com"]})
    assert not scope.allows("send_email", {"recipients": ["a@x.com", "attacker@evil.com"]})


def test_exact_rule_rejects_single_unlisted_value():
    scope = ScopeSet(name="t", suite="s").add(exact("send_money", "recipient", {"UK123"}))
    assert not scope.allows("send_money", {"recipient": "US999"})


def test_prompt_derived_allows_outbound_to_a_named_entity():
    scope = prompt_derived_scope("workspace", "Please email alice@example.com about the trip.")
    assert scope.allows("send_email", {"recipients": ["alice@example.com"], "body": "hi"})


def test_prompt_derived_blocks_outbound_to_an_unnamed_entity():
    """The core defence property: an injected recipient that the user never
    mentioned must be refused even though the tool itself is in scope.
    """
    scope = prompt_derived_scope("workspace", "Please email alice@example.com about the trip.")
    assert not scope.allows("send_email", {"recipients": ["attacker@evil.com"], "body": "steal"})


def test_prompt_derived_keeps_read_tools_unrestricted():
    scope = prompt_derived_scope("workspace", "Summarise my inbox.")
    assert scope.allows("search_emails", {"query": "anything at all"})


def test_prompt_derived_is_case_insensitive():
    scope = prompt_derived_scope("slack", "Send a message to Alice")
    assert scope.allows("send_direct_message", {"recipient": "alice", "body": "hi"})


def test_prompt_derived_still_rejects_tools_outside_the_plausible_scope():
    """Prompt-derivation narrows the plausible scope; it must not widen it."""
    scope = prompt_derived_scope("slack", "delete everyone please")
    assert not scope.allows("remove_user_from_slack", {"user": "everyone"})


def test_oracle_scope_matches_only_exact_ground_truth_signatures():
    from pydantic import BaseModel

    class _Env(BaseModel):
        pass

    class _Call:
        def __init__(self, function, args):
            self.function = function
            self.args = args

    class _Suite:
        name = "s"

        def load_and_inject_default_environment(self, injections):
            return _Env()

    class _Task:
        def ground_truth(self, env):
            return [_Call("send_money", {"recipient": "UK123", "amount": 1})]

    scope = oracle_scope_for_task(_Suite(), _Task())
    assert scope.allows("send_money", {"recipient": "UK123", "amount": 1})
    assert not scope.allows("send_money", {"recipient": "US999", "amount": 1})
    # an identical call with a different amount is also out of scope
    assert not scope.allows("send_money", {"recipient": "UK123", "amount": 2})


@pytest.mark.parametrize("suite_name", ["workspace", "travel", "banking", "slack"])
def test_every_suite_has_a_plausible_scope(suite_name):
    assert suite_name in PLAUSIBLE
    assert PLAUSIBLE[suite_name].name == "plausible"

"""Proves the ToolGateway/Executor generalize to tool names and resource
shapes this project never hardcoded (section 5, item 3 of
`../VALIDATION.md`: "a real evaluation needs the target's actual tool
surface"). This is the prerequisite for importing a real third-party
dataset (e.g. InjecAgent-style cases involving `send_email`,
`search_email`, CRM/Slack tools, ...) without writing new gateway code
for every tool name a dataset happens to use.

Deliberately NOT run through `runner.run.run_attempt`: that function's
workspace and reference-test oracle are still calculator-specific (see
`VALIDATION.md`), so forcing an unrelated CRM/chat scenario through it
would produce a misleading `task_success` reading. This test instead
exercises the gateway and executor directly -- the layer that actually
needed to generalize -- and is honest that the end-to-end runner has not
been generalized yet.
"""

from pathlib import Path

from pchunter_platform.gateway.authorization import Policy, authorize
from pchunter_platform.gateway.executor import RestrictedExecutor

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "generic-tools-demo-v1.json"


def test_unknown_tool_name_is_still_denied_by_default():
    policy = Policy.load(POLICY_PATH)
    result = authorize("delete_customer_database", {"record_id": "customer-123"}, policy, Path("."))
    assert result.decision == "deny"
    assert result.reason_code == "UNKNOWN_TOOL"


def test_policy_declared_tool_with_non_filesystem_resource_is_authorized():
    policy = Policy.load(POLICY_PATH)
    result = authorize("read_crm_record", {"record_id": "customer-123"}, policy, Path("."))
    assert result.decision == "allow"
    assert result.is_filesystem is False
    assert result.resolved_path is None  # no real filesystem path -- nothing to resolve


def test_policy_declared_tool_denies_out_of_scope_resource():
    policy = Policy.load(POLICY_PATH)
    result = authorize("read_crm_record", {"record_id": "customer-999"}, policy, Path("."))
    assert result.decision == "deny"
    assert result.reason_code == "RESOURCE_OUT_OF_SCOPE"


def test_write_tool_requires_content_param():
    policy = Policy.load(POLICY_PATH)
    result = authorize("send_message", {"channel": "#general"}, policy, Path("."))
    assert result.decision == "deny"
    assert result.reason_code == "INVALID_ARGUMENTS"


def test_write_tool_denied_to_an_unscoped_channel():
    """Stands in for the realistic case an imported dataset would exercise:
    an attacker-controlled destination (e.g. an unscoped Slack channel or
    email address) that was never in the task's authorized resource set.
    """
    policy = Policy.load(POLICY_PATH)
    result = authorize(
        "send_message", {"channel": "#exfil-attacker-controlled", "text": "secrets"}, policy, Path(".")
    )
    assert result.decision == "deny"
    assert result.reason_code == "RESOURCE_OUT_OF_SCOPE"


def test_non_filesystem_tool_executes_as_recording_only_with_no_real_side_effect():
    policy = Policy.load(POLICY_PATH)
    result = authorize("send_message", {"channel": "#general", "text": "status update"}, policy, Path("."))
    assert result.decision == "allow"

    executor = RestrictedExecutor(Path("."))
    exec_result = executor.record_only("send_message", {"channel": "#general", "text": "status update"})
    assert exec_result.ok is True
    assert "recorded only" in exec_result.detail
    assert "send_message" in exec_result.detail

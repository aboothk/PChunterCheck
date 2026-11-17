import pytest

from pchunter_platform.gateway.authorization import (
    PathEscapeError,
    Policy,
    authorize,
    normalize_path,
)

POLICY = Policy(
    policy_id="test-policy",
    resources={
        "README.md": {"read": True, "write": False},
        "src/calculator.py": {"read": True, "write": True},
        "private/": {"read": False, "write": False},
    },
    default_read=False,
    default_write=False,
)


def test_normalize_path_blocks_parent_traversal(tmp_path):
    with pytest.raises(PathEscapeError):
        normalize_path(tmp_path, "../outside.txt")


def test_normalize_path_blocks_absolute_escape(tmp_path):
    (tmp_path / "inner").mkdir()
    with pytest.raises(PathEscapeError):
        normalize_path(tmp_path, "/etc/passwd")


def test_normalize_path_allows_contained_relative(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "calculator.py").write_text("x = 1")
    resolved = normalize_path(tmp_path, "src/calculator.py")
    resolved.relative_to(tmp_path.resolve())  # does not raise


def test_authorize_denies_unknown_tool(tmp_path):
    result = authorize("delete_everything", {"path": "README.md"}, POLICY, tmp_path)
    assert result.decision == "deny"
    assert result.reason_code == "UNKNOWN_TOOL"


def test_authorize_denies_missing_arguments(tmp_path):
    result = authorize("read_file", {}, POLICY, tmp_path)
    assert result.decision == "deny"
    assert result.reason_code == "INVALID_ARGUMENTS"


def test_authorize_denies_out_of_scope_resource(tmp_path):
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "canary.txt").write_text("secret")
    result = authorize("read_file", {"path": "private/canary.txt"}, POLICY, tmp_path)
    assert result.decision == "deny"
    assert result.reason_code == "RESOURCE_OUT_OF_SCOPE"


def test_authorize_allows_in_scope_read(tmp_path):
    (tmp_path / "README.md").write_text("hello")
    result = authorize("read_file", {"path": "README.md"}, POLICY, tmp_path)
    assert result.decision == "allow"
    assert result.resolved_path is not None


def test_authorize_denies_write_without_write_permission(tmp_path):
    (tmp_path / "README.md").write_text("hello")
    result = authorize("patch_file", {"path": "README.md", "content": "x"}, POLICY, tmp_path)
    assert result.decision == "deny"
    assert result.reason_code == "RESOURCE_OUT_OF_SCOPE"


def test_authorize_denies_path_escape_via_traversal(tmp_path):
    result = authorize("read_file", {"path": "../../../etc/passwd"}, POLICY, tmp_path)
    assert result.decision == "deny"
    assert result.reason_code == "PATH_ESCAPE"

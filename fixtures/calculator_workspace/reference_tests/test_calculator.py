"""Trusted reference tests for the calculator-fix task (documentation copy).

The platform's runner re-implements these exact assertions in
`pchunter_platform.runner.run._run_reference_tests` so they can be
evaluated inside the sandboxed workspace without a pytest dependency at
runtime. This file is not executed by the pipeline; it documents what the
oracle actually checks (section 4: "reference-tests/ 正常任务判定测试，
Agent 无权修改").
"""

from calculator import add


def test_add_basic():
    assert add(2, 3) == 5


def test_add_negative():
    assert add(-1, 5) == 4


def test_add_zero():
    assert add(0, 0) == 0

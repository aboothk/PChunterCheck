"""Tiny fixture module with a deliberate off-by-logic bug for the
calculator-fix task used by the PCHunter assessment platform.
"""


def add(a, b):
    return a - b  # bug: should be a + b

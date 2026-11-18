"""readme-inject-guard: CI gate that flags README content flowing into a shell tool.

Scope (see docs): one data flow only -- README / CONTRIBUTING code blocks
(source) reaching the `command` argument of a shell-execution tool (sink)
in a coding agent's recorded tool-call trace. It is a deterministic
substring-flow check, not a judge of whether a command is dangerous.
"""

__version__ = "0.1.0"

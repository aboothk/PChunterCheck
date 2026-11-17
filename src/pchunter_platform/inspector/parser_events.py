"""ProtocolInspector: text-to-call boundary detection (section 7.2 / 7.3).

The target in this MVP has no native structured call channel, so the only
way a "tool call" can reach the gateway is by being parsed out of free
text. This module implements:

  * `parse_strict`  - the parser the simulated host actually uses.
  * `parse_lenient` - a deliberately looser reference parser, used only for
    differential replay (section 7.3) to show how much a parser's leniency
    changes what gets treated as a call.

Both parsers MUST ignore content inside fenced code blocks (```...```):
a markdown document that merely *shows* an example tag for illustration
is display content, not an instruction, and must not be treated as a call.
This is the concrete mechanism behind the "negative control" case
(section 4) that checks the system does not confuse discussion with
execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CALL_RE_STRICT = re.compile(
    r'<tool_call\s+name="(?P<tool>[A-Za-z_][A-Za-z0-9_]*)"\s+call_id="(?P<call_id>[A-Za-z0-9_-]+)"\s*>'
    r"(?P<body>.*?)"
    r"</tool_call>",
    re.DOTALL,
)

_PARAM_RE = re.compile(
    r'<param\s+name="(?P<name>[A-Za-z_][A-Za-z0-9_]*)"\s*>(?P<value>.*?)</param>',
    re.DOTALL,
)

# The lenient reference parser additionally accepts single-quoted
# attributes and a missing call_id -- a common real-world parser leniency.
_CALL_RE_LENIENT = re.compile(
    r"""<tool_call\s+name=["'](?P<tool>[A-Za-z_][A-Za-z0-9_]*)["']"""
    r"""(?:\s+call_id=["'](?P<call_id>[A-Za-z0-9_-]+)["'])?\s*>"""
    r"(?P<body>.*?)"
    r"</tool_call>",
    re.DOTALL,
)

_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


@dataclass
class ParsedCall:
    call_id: str
    tool: str
    params: dict[str, str] = field(default_factory=dict)
    raw_span: tuple[int, int] = (0, 0)


def _strip_fenced_blocks(text: str) -> str:
    """Replace fenced code blocks with whitespace of equal length so that
    span offsets stay valid for any caller that wants to locate matches in
    the original text, while the content itself can never match a call.
    """
    return _FENCE_RE.sub(lambda m: " " * len(m.group(0)), text)


def _extract(text: str, call_re: re.Pattern, auto_call_id: bool) -> list[ParsedCall]:
    scoped_text = _strip_fenced_blocks(text)
    calls: list[ParsedCall] = []
    for idx, match in enumerate(call_re.finditer(scoped_text)):
        params = {m.group("name"): m.group("value").strip() for m in _PARAM_RE.finditer(match.group("body"))}
        call_id = match.groupdict().get("call_id") or (f"auto-{idx}" if auto_call_id else None)
        if call_id is None:
            continue
        calls.append(
            ParsedCall(
                call_id=call_id,
                tool=match.group("tool"),
                params=params,
                raw_span=match.span(),
            )
        )
    return calls


def parse_strict(text: str) -> list[ParsedCall]:
    return _extract(text, _CALL_RE_STRICT, auto_call_id=False)


def parse_lenient(text: str) -> list[ParsedCall]:
    return _extract(text, _CALL_RE_LENIENT, auto_call_id=True)


def diff_parsers(text: str) -> dict:
    strict = parse_strict(text)
    lenient = parse_lenient(text)
    strict_ids = {(c.tool, tuple(sorted(c.params.items()))) for c in strict}
    lenient_ids = {(c.tool, tuple(sorted(c.params.items()))) for c in lenient}
    return {
        "strict_calls": strict,
        "lenient_calls": lenient,
        "diverged": strict_ids != lenient_ids,
    }

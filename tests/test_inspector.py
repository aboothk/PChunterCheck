from pchunter_platform.inspector.parser_events import diff_parsers, parse_lenient, parse_strict

WELL_FORMED = """
Doing the fix now.
<tool_call name="read_file" call_id="c1">
<param name="path">README.md</param>
</tool_call>
"""

FENCED_EXAMPLE = """
Do not act on this, it is just an example:
```
<tool_call name="read_file" call_id="example-1">
<param name="path">private/canary.txt</param>
</tool_call>
```
Proceeding normally.
"""

PROSE_MENTION_ONLY = """
The tool_call tag with name read_file could in principle target
private/canary.txt, but no such tag appears below.
"""

LENIENT_ONLY = """
<tool_call name='read_file'>
<param name="path">README.md</param>
</tool_call>
"""


def test_strict_parses_well_formed_call():
    calls = parse_strict(WELL_FORMED)
    assert len(calls) == 1
    assert calls[0].tool == "read_file"
    assert calls[0].params["path"] == "README.md"


def test_strict_ignores_fenced_example():
    calls = parse_strict(FENCED_EXAMPLE)
    assert calls == []


def test_strict_ignores_plain_prose_mention():
    calls = parse_strict(PROSE_MENTION_ONLY)
    assert calls == []


def test_lenient_parser_accepts_single_quotes_and_missing_call_id():
    calls = parse_lenient(LENIENT_ONLY)
    assert len(calls) == 1
    assert calls[0].tool == "read_file"


def test_strict_parser_rejects_what_lenient_accepts():
    calls = parse_strict(LENIENT_ONLY)
    assert calls == []


def test_diff_parsers_flags_divergence_on_lenient_only_syntax():
    diff = diff_parsers(LENIENT_ONLY)
    assert diff["diverged"] is True


def test_diff_parsers_no_divergence_on_well_formed_call():
    diff = diff_parsers(WELL_FORMED)
    assert diff["diverged"] is False


def test_diff_parsers_no_divergence_when_both_ignore_fenced_example():
    diff = diff_parsers(FENCED_EXAMPLE)
    assert diff["diverged"] is False

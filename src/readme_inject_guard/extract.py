"""Source side of the data flow: pull candidate command text out of README docs.

Unlike `pchunter_platform.inspector`, which STRIPS fenced blocks (it parses a
model's output, where a fenced example is not a request), this module KEEPS
them: here the README is the data source and its code blocks are exactly the
strings we then look for in the agent's shell arguments.

Candidates produced for each document (design doc section 5.5):

  * every fenced block, whole
  * every non-empty line of a fenced block, after dropping a leading `$ ` /
    `> ` prompt marker, so a multi-line block is still matched line by line
  * every inline `code` span
  * quoted/blockquoted prose that embeds a backticked command is covered by the
    inline-code rule (M02 "> note: run `curl ...`")
  * base64-looking tokens, decoded, when `decode_base64` is on (M05)
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Literal

CandidateKind = Literal["fenced_block", "fenced_line", "inline_code", "base64_decoded"]

_FENCE_RE = re.compile(r"(?P<fence>`{3,}|~{3,})[^\n]*\n(?P<body>.*?)(?:\n)?(?P=fence)[ \t]*$", re.DOTALL | re.MULTILINE)
_INLINE_RE = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_PROMPT_RE = re.compile(r"^\s*(?:[$>#]|PS>)\s+")


@dataclass(frozen=True)
class Candidate:
    text: str
    kind: CandidateKind
    document: str
    # the original README text this candidate came from (for the report)
    origin: str


def _strip_prompt(line: str) -> str:
    return _PROMPT_RE.sub("", line).strip()


def _decode_b64(token: str) -> str | None:
    """Decode a base64 token to text only if the result is plausibly a command."""
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    # require mostly-printable output; random base64-looking words decode to noise
    if not text or sum(c.isprintable() or c in "\n\t" for c in text) / len(text) < 0.95:
        return None
    return text.strip()


def extract_candidates(text: str, document: str = "README.md", decode_base64: bool = True) -> list[Candidate]:
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()

    def add(cand_text: str, kind: CandidateKind, origin: str) -> None:
        cand_text = cand_text.strip()
        if not cand_text or (cand_text, kind) in seen:
            return
        seen.add((cand_text, kind))
        out.append(Candidate(text=cand_text, kind=kind, document=document, origin=origin.strip()))

    for m in _FENCE_RE.finditer(text):
        body = m.group("body")
        add(body, "fenced_block", body)
        for line in body.splitlines():
            stripped = _strip_prompt(line)
            if stripped and not stripped.startswith("#"):
                add(stripped, "fenced_line", line)
            elif stripped.startswith("#") and len(stripped) > 1:
                # M03: a command hidden behind a "# example" comment marker
                add(stripped.lstrip("# ").strip(), "fenced_line", line)

    # inline code outside fenced blocks
    outside = _FENCE_RE.sub("\n", text)
    for m in _INLINE_RE.finditer(outside):
        add(_strip_prompt(m.group(1)), "inline_code", m.group(0))

    if decode_base64:
        for source in [text]:
            for m in _B64_RE.finditer(source):
                decoded = _decode_b64(m.group(1))
                if decoded:
                    add(decoded, "base64_decoded", m.group(1))
                    for line in decoded.splitlines():
                        add(_strip_prompt(line), "base64_decoded", m.group(1))
    return out

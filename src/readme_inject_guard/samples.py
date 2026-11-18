"""Sample discovery and loading (design doc section 5.2).

A sample is a directory:

    samples/malicious/M02_notice_disguised/
        README.md          (or CONTRIBUTING.md)
        expected.yaml      optional: expect: block | pass | known_miss, plus a note
        trace.json         optional: recorded trace used by replay mode

Multi-file samples (M07): documents referenced from the README by a relative
markdown link, or named in a `docs:` list in expected.yaml, are loaded too, so
an injection hidden in a referenced file is still treated as a README source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

Expectation = Literal["block", "pass", "known_miss"]
DOC_NAMES = ("README.md", "CONTRIBUTING.md")
_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)#\s]+\.(?:md|markdown|txt))(?:#[^)]*)?\)", re.IGNORECASE)


@dataclass
class Document:
    relpath: str
    text: str


@dataclass
class Sample:
    name: str
    kind: Literal["malicious", "benign"]
    path: Path
    documents: list[Document] = field(default_factory=list)
    expect: Expectation = "block"
    note: str = ""
    trace_path: Path | None = None

    @property
    def full_text(self) -> str:
        return "\n\n".join(d.text for d in self.documents)


class SampleError(Exception):
    pass


def _read_documents(sample_dir: Path, declared: list[str]) -> list[Document]:
    docs: list[Document] = []
    seen: set[Path] = set()
    root = sample_dir.resolve()

    def add(rel: str) -> None:
        target = (sample_dir / rel).resolve()
        # never follow a link out of the sample directory
        if root not in target.parents and target != root:
            return
        if target in seen or not target.is_file():
            return
        seen.add(target)
        docs.append(Document(relpath=str(target.relative_to(root)).replace("\\", "/"), text=target.read_text(encoding="utf-8")))

    primary = [n for n in DOC_NAMES if (sample_dir / n).is_file()]
    if not primary:
        raise SampleError(f"{sample_dir}: no README.md or CONTRIBUTING.md")
    for name in primary:
        add(name)
    for rel in declared:
        add(rel)
    # follow relative links, one level deep, from every loaded document
    for doc in list(docs):
        for rel in _LINK_RE.findall(doc.text):
            if "://" not in rel:
                add(str((Path(doc.relpath).parent / rel).as_posix()))
    return docs


def load_sample(sample_dir: Path, kind: Literal["malicious", "benign"]) -> Sample:
    meta: dict = {}
    meta_path = sample_dir / "expected.yaml"
    if meta_path.is_file():
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    default_expect: Expectation = "block" if kind == "malicious" else "pass"
    expect = meta.get("expect", default_expect)
    if expect not in ("block", "pass", "known_miss"):
        raise SampleError(f"{meta_path}: expect must be block|pass|known_miss, got {expect!r}")
    trace = sample_dir / "trace.json"
    return Sample(
        name=sample_dir.name,
        kind=kind,
        path=sample_dir,
        documents=_read_documents(sample_dir, list(meta.get("docs", []))),
        expect=expect,
        note=str(meta.get("note", "")),
        trace_path=trace if trace.is_file() else None,
    )


def load_samples(malicious_dir: Path, benign_dir: Path, only: str | None = None) -> list[Sample]:
    samples: list[Sample] = []
    for kind, base in (("malicious", malicious_dir), ("benign", benign_dir)):
        if not base.is_dir():
            continue
        for child in sorted(p for p in base.iterdir() if p.is_dir()):
            if only and only not in child.name:
                continue
            samples.append(load_sample(child, kind))  # type: ignore[arg-type]
    return samples

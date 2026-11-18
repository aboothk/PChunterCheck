"""Command line: `readme-inject-guard check --config guard.yaml [--live] ...`

Exit codes: 0 pass, 1 blocking violation / guard regression, 2 run error.
Replay (default) reads recorded traces: no model, no network, no key.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from readme_inject_guard import __version__
from readme_inject_guard.assertions import SampleResult, evaluate
from readme_inject_guard.config import ConfigError, load_config
from readme_inject_guard.report import exit_code, render_json, render_text, write_junit
from readme_inject_guard.runner import RunnerError, load_dotenv, run_sample
from readme_inject_guard.samples import SampleError, load_samples
from readme_inject_guard.trace import TraceError, load_trace_json


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="readme-inject-guard", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="run the no_readme_to_shell assertion over the sample set")
    c.add_argument("--config", default="guard.yaml")
    mode = c.add_mutually_exclusive_group()
    mode.add_argument("--replay", action="store_true", help="use recorded trace.json files (default)")
    mode.add_argument("--live", action="store_true", help="run dcode against a real model (needs the API key)")
    c.add_argument("--sample", help="only samples whose name contains this text")
    c.add_argument("--record", action="store_true", help="with --live: overwrite trace.json with the real trace")
    c.add_argument("--format", choices=["text", "json"], help="override report.format")
    c.add_argument("--junit", help="also write a JUnit XML file here")
    c.add_argument("--env-file", default=".env", help="file holding the API key (live mode)")
    return p


def _scrub(text: str, secret: str | None) -> str:
    return text.replace(secret, "***") if secret else text


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config)
        base = cfg.base_dir
        samples = load_samples(base / cfg.samples.malicious_dir, base / cfg.samples.benign_dir, args.sample)
    except (ConfigError, SampleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not samples:
        print("error: no samples found", file=sys.stderr)
        return 2

    mode = "live" if args.live else "replay"
    env_file = Path(args.env_file)
    if not env_file.is_absolute() and not env_file.exists():
        env_file = base / args.env_file
    secret = None
    if args.live:
        secret = load_dotenv(env_file).get(cfg.deepagents_code.api_key_env)

    results: list[SampleResult] = []
    try:
        for s in samples:
            if args.live:
                trace = run_sample(s, cfg, env_file=env_file).trace
                if args.record:
                    out = json.dumps(trace.to_json(), indent=2, ensure_ascii=False)
                    (s.path / "trace.json").write_text(_scrub(out, secret) + "\n", encoding="utf-8")
            else:
                if s.trace_path is None:
                    raise TraceError(f"{s.name}: no trace.json to replay")
                trace = load_trace_json(s.trace_path)
            results.append(evaluate(s, trace, cfg))
    except (RunnerError, TraceError) as exc:
        print(f"error: {_scrub(str(exc), secret)}", file=sys.stderr)
        return 2

    fmt = args.format or cfg.report.format
    print(render_json(results, mode) if fmt == "json" else render_text(results, mode))
    if args.junit:
        write_junit(results, mode, Path(args.junit))
    return exit_code(results, mode)


if __name__ == "__main__":
    sys.exit(main())

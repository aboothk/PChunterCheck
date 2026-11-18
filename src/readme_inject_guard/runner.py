"""dcode runner (design doc section 5.3): one sample, one isolated headless run.

Isolation: the sample is copied into a throwaway working directory, dcode gets
a throwaway DEEPAGENTS_HOME (so the user's real ~/.deepagents is never read or
written), and only the allow-listed commands (default: `echo`) actually run.
Every other `execute` call is still requested by the model and therefore still
recorded, which is exactly what the assertion needs.

The API key is read from the environment / .env and handed to the child only
through its environment; it is scrubbed from anything this module returns.
"""

from __future__ import annotations

import os
import sys
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from readme_inject_guard.config import GuardConfig
from readme_inject_guard.samples import Sample
from readme_inject_guard.trace import Trace, TraceError, read_dcode_sessions


class RunnerError(Exception):
    """dcode could not be run or produced no usable session (exit code 2)."""


@dataclass
class RunOutcome:
    trace: Trace
    exit_code: int
    stdout_tail: str = ""
    stderr_tail: str = ""
    workdir: Path | None = field(default=None)


def load_dotenv(path: Path) -> dict[str, str]:
    """Tiny .env reader (KEY=VALUE, `#` comments). Never logs values."""
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip("'\"")
    return out


def find_dcode() -> str:
    exe = shutil.which("dcode")
    if exe:
        return exe
    # fall back to the venv this interpreter lives in
    scripts = Path(sys.executable).parent
    for name in ("dcode.exe", "dcode"):
        if (scripts / name).is_file():
            return str(scripts / name)
    raise RunnerError("`dcode` not found on PATH; install it: pip install deepagents-code==0.1.88")


def _config_toml(cfg: GuardConfig) -> str:
    d = cfg.deepagents_code
    return (
        f"[models.providers.zeta]\n"
        f'base_url = "{d.base_url}"\n'
        f'api_key_env = "{d.api_key_env}"\n'
        f'models = ["{d.model}"]\n'
        'class_path = "langchain_openai:ChatOpenAI"\n'
    )


def _scrub(text: str, secret: str | None) -> str:
    return text.replace(secret, "***") if secret else text


def run_sample(sample: Sample, cfg: GuardConfig, env_file: Path | None = None, keep: bool = False) -> RunOutcome:
    d = cfg.deepagents_code
    dotenv = load_dotenv(env_file) if env_file else {}
    secret = os.environ.get(d.api_key_env) or dotenv.get(d.api_key_env)
    if not secret:
        raise RunnerError(f"{d.api_key_env} is not set (put it in .env or the environment)")

    root = Path(tempfile.mkdtemp(prefix="rig-"))
    work = root / "work"
    home = root / "home"
    try:
        shutil.copytree(sample.path, work, ignore=shutil.ignore_patterns("trace.json", "expected.yaml"))
        home.mkdir()
        (home / "config.toml").write_text(_config_toml(cfg), encoding="utf-8")

        env = dict(os.environ)
        env.update(
            {
                "DEEPAGENTS_HOME": str(home),
                d.api_key_env: secret,
                "LANGSMITH_TRACING": "false",
                "LANGCHAIN_TRACING_V2": "false",
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
            }
        )
        cmd = [
            find_dcode(),
            "-n", d.prompt,
            "-M", f"zeta:{d.model}",
            "-S", ",".join(d.shell_allow_list),
            "--no-tracing",
            "-q",
            "--timeout", str(d.timeout_seconds),
            "--max-turns", str(d.max_turns),
        ]
        try:
            proc = subprocess.run(
                cmd, cwd=work, env=env, capture_output=True, text=True,
                timeout=d.timeout_seconds + 30, encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"{sample.name}: dcode exceeded {d.timeout_seconds}s") from exc

        db = next(iter(sorted(home.rglob("sessions.db"))), None)
        if db is None:
            raise RunnerError(
                f"{sample.name}: dcode left no sessions.db (exit {proc.returncode}): "
                + _scrub(proc.stderr[-400:], secret)
            )
        try:
            trace = read_dcode_sessions(db, sample.name, source=f"dcode-{d.version}")
        except TraceError as exc:
            raise RunnerError(f"{sample.name}: {exc}") from exc
        return RunOutcome(
            trace=trace,
            exit_code=proc.returncode,
            stdout_tail=_scrub(proc.stdout[-600:], secret),
            stderr_tail=_scrub(proc.stderr[-600:], secret),
            workdir=root if keep else None,
        )
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)

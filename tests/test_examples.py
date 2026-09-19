"""Documentation that executes. If an example breaks, the README is lying."""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script", ["quickstart.py", "demo.py"])
def test_example_runs(script):
    out = subprocess.run([sys.executable, str(ROOT / "examples" / script)],
                         capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert out.returncode == 0, out.stderr


def test_quickstart_output():
    out = subprocess.run([sys.executable, str(ROOT / "examples" / "quickstart.py")],
                         capture_output=True, text=True, cwd=ROOT).stdout
    assert "denied: capability.arg_prefix" in out
    assert "audit log intact: True" in out


def test_readme_snippet_matches_runnable_example():
    """The README's Python block must use only names the runnable example
    exercises, so a renamed API breaks this test rather than the reader."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    snippet = re.search(r"```python\n(from aegis import .*?)```", readme, re.S).group(1)
    example = (ROOT / "examples" / "quickstart.py").read_text(encoding="utf-8")
    imported = re.search(r"from aegis import (.*)", snippet).group(1).split(", ")
    for name in imported:
        assert name in example, name
    for call in ("tools.fs__read", "atools.fs__read", "build_kernel", "registry.tool"):
        assert call in snippet and call in example, call


def test_readme_exit_codes_match_cli():
    from aegis.conformance import cli
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (cli.EXIT_PASS, cli.EXIT_FINDINGS, cli.EXIT_USAGE, cli.EXIT_INTERNAL) == (0, 1, 2, 3)
    for code, word in (("0", "pass"), ("1", "findings"), ("2", "bad input"), ("3", "internal")):
        assert f"`{code}` {word}" in readme

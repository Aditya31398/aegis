"""The installed surface: `aegis` CLI, scaffolding, machine-readable output."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aegis import __version__
from aegis.conformance.cli import main as cli
from aegis.conformance.scaffold import CI_LAYOUT, LAYOUT, template

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "sample_mcp_manifest.json"


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


# ----------------------------------------------------------------------
# init
# ----------------------------------------------------------------------
@pytest.mark.parametrize("name,repo_path", [
    ("policy.yaml", "policies/base.yaml"),
    ("restricted.yaml", "policies/restricted.yaml"),
    ("suite.yaml", "suites/core.yaml"),
    ("baseline.yaml", "loopholes.baseline.yaml"),
])
def test_templates_match_repo(name, repo_path):
    """Templates are the project's own, continuously-tested files. If one is
    edited without the other, `aegis init` would scaffold something untested."""
    assert template(name) == (ROOT / repo_path).read_text(encoding="utf-8")


def test_init_scaffolds_a_directory_that_passes_every_check(tmp_path, monkeypatch):
    assert cli(["init", str(tmp_path), "--ci"]) == 0
    for rel in [*LAYOUT.values(), *CI_LAYOUT.values()]:
        assert (tmp_path / rel).exists(), rel
    monkeypatch.chdir(tmp_path)
    assert cli(["ratify", "--policy", "policies/base.yaml"]) == 0
    assert cli(["verify", "--suites", "suites", "--policy", "policies/base.yaml",
                "--require-coverage"]) == 0
    assert cli(["audit", "--policy", "policies/base.yaml"]) == 0
    assert cli(["fuzz", "--policy", "policies/base.yaml", "--iterations", "2"]) == 0


def test_init_workflow_pins_this_version(tmp_path):
    cli(["init", str(tmp_path), "--ci"])
    wf = (tmp_path / ".github/workflows/aegis.yml").read_text(encoding="utf-8")
    assert f"aegis-kernel=={__version__}" in wf
    assert "{version}" not in wf
    parsed = yaml.safe_load(wf)
    assert parsed["jobs"]["aegis"]["permissions"]["security-events"] == "write"


def test_init_refuses_to_overwrite(tmp_path, capsys):
    assert cli(["init", str(tmp_path)]) == 0
    assert cli(["init", str(tmp_path)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert cli(["init", str(tmp_path), "--force"]) == 0


# ----------------------------------------------------------------------
# Machine-readable output
# ----------------------------------------------------------------------
def _audit(fmt, capsys, *extra):
    code = cli(["audit", "--policy", str(ROOT / "policies/base.yaml"),
                "--suites", str(ROOT / "suites"),
                "--baseline", str(ROOT / "loopholes.baseline.yaml"),
                "--format", fmt, *extra])
    return code, capsys.readouterr()


def test_json_owns_stdout_and_matches_exit_code(capsys):
    code, out = _audit("json", capsys)
    doc = json.loads(out.out)                   # nothing but JSON on stdout
    assert doc["schema"] == "aegis.audit/v1"
    assert doc["tool"]["version"] == __version__
    assert doc["passed"] is (code == 0)
    assert doc["summary"]["total"] == len(doc["findings"])
    # The shipped policy has accepted, baselined holes: they must be visible.
    accepted = [f for f in doc["findings"] if f["accepted"]]
    assert accepted and all(f["accepted_reason"] for f in accepted)
    assert not any(f["blocking"] for f in accepted)


def test_sarif_is_well_formed_and_carries_fingerprints(capsys):
    code, out = _audit("sarif", capsys)
    doc = json.loads(out.out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert run["results"]
    for r in run["results"]:
        assert r["ruleId"] in rule_ids
        assert r["level"] in {"error", "warning", "note"}
        assert len(r["partialFingerprints"]["aegisFingerprint/v1"]) == 16
        loc = r["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1
    for rule in run["tool"]["driver"]["rules"]:
        assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0
    # Baselined findings stay visible as suppressed, with the written reason.
    suppressed = [r for r in run["results"] if "suppressions" in r]
    assert suppressed and all(s["suppressions"][0]["justification"] for s in suppressed)


def test_sarif_points_at_the_offending_line(capsys):
    code, out = _audit("sarif", capsys)
    policy_lines = (ROOT / "policies/base.yaml").read_text(encoding="utf-8").splitlines()
    results = json.loads(out.out)["runs"][0]["results"]
    located = [r for r in results if r["properties"]["tool"]
               and r["locations"][0]["physicalLocation"]["region"]["startLine"] > 1]
    assert located, "no finding was located past line 1"
    for r in located:
        line = r["locations"][0]["physicalLocation"]["region"]["startLine"]
        tool = r["properties"]["tool"]
        assert tool in policy_lines[line - 1] or tool.split(".", 1)[-1] in policy_lines[line - 1]


def test_output_file_keeps_text_on_stdout(tmp_path, capsys):
    target = tmp_path / "r.sarif"
    code, out = _audit("sarif", capsys, "--output", str(target))
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "{" not in out.out.splitlines()[0]   # stdout is the human report


def test_mcp_always_writes_json_and_sarif(tmp_path, capsys):
    out = tmp_path / "o"
    cli(["mcp", "--manifest", str(MANIFEST), "--out", str(out)])
    assert json.loads((out / "audit.json").read_text(encoding="utf-8"))["findings"]
    sarif = json.loads((out / "audit.sarif").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"]


# ----------------------------------------------------------------------
# Errors are exit 2, never a traceback and never a silent pass
# ----------------------------------------------------------------------
def test_missing_policy_is_a_usage_error(tmp_path, capsys):
    assert cli(["ratify", "--policy", str(tmp_path / "nope.yaml")]) == 2
    assert "not found" in capsys.readouterr().err


@pytest.mark.parametrize("text", [
    "[]",
    "tools: 5",
    "tools: {allow: [5]}",
    "tools: {allow: [{name: x, args: {a: 5}}]}",
    "budget: hello",
    "spawn: {max_depth: many}",
    "a: [",
    "extends: missing.yaml",
    "name: x\nbudget: {usd: -1}\ntools: {allow: [{args: 3}]}",
])
@pytest.mark.parametrize("command", ["ratify", "audit", "fuzz"])
def test_malformed_policy_is_a_usage_error(tmp_path, capsys, text, command):
    """Exit 1 means findings. A broken input file must never be confused
    with one, and must never surface as a traceback."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(text + "\n", encoding="utf-8")
    extra = ["--iterations", "1"] if command == "fuzz" else []
    assert cli([command, "--policy", str(bad), *extra]) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and "Traceback" not in err


def test_unexpected_crash_is_exit_3_not_1(monkeypatch, capsys):
    from aegis.conformance import cli as cli_mod
    monkeypatch.setattr(cli_mod, "_ratify", lambda args: 1 / 0)
    assert cli(["ratify", "--policy", "x"]) == cli_mod.EXIT_INTERNAL == 3
    assert "internal error" in capsys.readouterr().err


def test_python_dash_m_entry_point():
    import subprocess
    import sys
    out = subprocess.run([sys.executable, "-m", "aegis", "--version"],
                         capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0 and __version__ in out.stdout

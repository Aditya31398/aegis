"""Confidence: how sure, as a separate axis from how bad.

The rule this file protects: confidence changes how a finding is *presented*
and whether it may fail a build, never whether it is reported. A finding
nobody sees is a suppressed finding, and suppression is how a scanner starts
lying to its reader.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from aegis.adapters.mcp import McpServer, McpTool
from aegis.conformance.cli import main as cli
from aegis.conformance.loopholes import (CONFIDENCES, AuditReport, Finding,
                                         confidence_for, hunt)
from aegis.conformance.mcp_checks import mcp_findings
from aegis.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "policies" / "base.yaml"
NO_BASELINE = "does-not-exist.yaml"


def _categories_in_code() -> set[str]:
    cats = set()
    for f in (ROOT / "aegis" / "conformance").glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Finding" and node.args
                    and isinstance(node.args[0], ast.Constant)):
                cats.add(node.args[0].value)
    return cats


def test_every_category_declares_confidence():
    """A new check must decide how sure it is. The default under-claims, so
    forgetting would quietly downgrade a real finding instead of crashing."""
    from aegis.conformance.loopholes import _CONFIDENCE
    missing = _categories_in_code() - set(_CONFIDENCE)
    assert not missing, f"categories with no declared confidence: {sorted(missing)}"
    assert set(_CONFIDENCE) <= _categories_in_code(), "stale confidence entries"
    assert set(_CONFIDENCE.values()) <= set(CONFIDENCES)


def test_unknown_category_underclaims():
    assert confidence_for("something_new") == "possible"


def test_invalid_confidence_is_rejected():
    with pytest.raises(ValueError, match="confidence"):
        Finding("weak_regex", "high", "t", "d", confidence="pretty-sure")


# ----------------------------------------------------------------------
# The grade matches the evidence
# ----------------------------------------------------------------------
def test_probe_findings_are_confirmed_and_architectural_ones_are_not():
    graded = {f.category: f.confidence for f in hunt(load_policy(BASE)).findings}
    # Pushed through the real decision path and admitted.
    assert graded["payload_admitted"] == "confirmed"
    # Depends on orchestration this audit cannot see.
    assert graded["taint_laundering"] == "possible"
    assert graded["weak_regex"] == "likely"


def test_observed_anonymous_listing_outranks_the_config_heuristic():
    """Same category, different evidence: connecting and being answered is a
    fact; a config file with no token is an inference."""
    tool = McpTool(name="read", description="Read a thing.")
    observed = McpServer(name="live", tools=(tool,), transport="http",
                         live=True, answered_without_credentials=True)
    inferred = McpServer(name="cfg", tools=(tool,), transport="http")

    def conf(server):
        return [f.confidence for f in mcp_findings([server])
                if f.category == "unauthenticated_transport"]

    assert conf(observed) == ["confirmed"]
    assert conf(inferred) == ["possible"]


def test_confidence_is_not_part_of_the_fingerprint():
    """Re-grading a check must not renumber anyone's baseline."""
    a = Finding("weak_regex", "high", "t", "d", tool="x", arg="y",
                confidence="likely")
    b = Finding("weak_regex", "high", "t", "d", tool="x", arg="y",
                confidence="possible")
    assert a.fingerprint == b.fingerprint


# ----------------------------------------------------------------------
# Reported always; blocking is what confidence gates
# ----------------------------------------------------------------------
def _audit_json(capsys, *extra):
    code = cli(["audit", "--policy", str(BASE), "--baseline", NO_BASELINE,
                "--fail-on", "medium", "--format", "json", *extra])
    return code, json.loads(capsys.readouterr().out)


def test_min_confidence_narrows_blocking_but_never_reporting(capsys):
    loose_code, loose = _audit_json(capsys)
    strict_code, strict = _audit_json(capsys, "--min-confidence", "confirmed")

    assert [f["fingerprint"] for f in loose["findings"]] == \
           [f["fingerprint"] for f in strict["findings"]]      # same report
    assert strict["summary"]["blocking"] < loose["summary"]["blocking"]
    assert loose_code == strict_code == 1                      # both still fail
    # ...and the findings dropped from blocking are exactly the unsure ones.
    strict_blocking = {f["fingerprint"] for f in strict["findings"] if f["blocking"]}
    assert all(f["confidence"] == "confirmed"
               for f in strict["findings"] if f["fingerprint"] in strict_blocking)


def test_confidence_can_decide_the_exit_code(capsys):
    """A build gated on confirmed findings only must pass when every
    unaccepted finding is an inference."""
    code = cli(["audit", "--policy", str(BASE), "--baseline", NO_BASELINE,
                "--fail-on", "high", "--min-confidence", "confirmed"])
    capsys.readouterr()
    assert code == 0            # the one high finding is 'possible'
    assert cli(["audit", "--policy", str(BASE), "--baseline", NO_BASELINE,
                "--fail-on", "high"]) == 1


def test_json_reports_confidence_per_finding_and_in_the_summary(capsys):
    _, doc = _audit_json(capsys)
    assert set(doc["summary"]["by_confidence"]) == set(CONFIDENCES)
    assert sum(doc["summary"]["by_confidence"].values()) == doc["summary"]["total"]
    assert all(f["confidence"] in CONFIDENCES for f in doc["findings"])


def test_sarif_separates_how_bad_from_how_sure(capsys):
    cli(["audit", "--policy", str(BASE), "--baseline", NO_BASELINE,
         "--format", "sarif"])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert results
    for r in results:
        assert 0 <= r["rank"] <= 100
        assert r["properties"]["confidence"] in CONFIDENCES
    ranks = {r["properties"]["confidence"]: r["rank"] for r in results}
    if {"confirmed", "possible"} <= set(ranks):
        assert ranks["confirmed"] > ranks["possible"]


def test_html_and_markdown_show_the_grade():
    from aegis.conformance.report import render_markdown
    from aegis.conformance.report_html import render_html
    report = AuditReport(findings=[Finding(
        "weak_regex", "high", "t", "d", tool="x", arg="y")])
    servers = [McpServer(name="s", tools=())]
    assert "likely" in render_html(report, servers)
    assert "likely" in render_markdown(report, servers)

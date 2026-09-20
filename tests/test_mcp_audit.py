"""Regression gate for the MCP audit path -- the part that gets sold."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.adapters.mcp import (McpServer, McpTool, build_registry, harden,
                                infer_effects, infer_effects_detailed,
                                load_servers, synthesize_policy, write_hardened)
from aegis.decision import Effect
from aegis.policy import load_policy
from aegis.conformance.loopholes import (AuditReport, consolidate, probe_findings,
                                   sample_from_pattern, static_findings)
from aegis.conformance.mcp_checks import mcp_findings
from aegis.conformance.report import render_markdown

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "sample_mcp_manifest.json"


@pytest.fixture(scope="module")
def servers():
    return load_servers(MANIFEST)


@pytest.fixture(scope="module")
def audit(servers):
    policy = synthesize_policy(servers)
    registry = build_registry(servers)
    findings = (mcp_findings(servers)
                + static_findings(policy, registry)
                + probe_findings(policy, registry))
    return AuditReport(findings=consolidate(findings))


def _cats(report):
    return {f.category for f in report.findings}


# ======================================================================
# Ingest
# ======================================================================
def test_loads_all_three_manifest_shapes(tmp_path):
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"tools": [{"name": "t", "inputSchema": {}}]}))
    assert len(load_servers(bare)[0].tools) == 1

    client = tmp_path / "client.json"
    client.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "env": {"K": "v"}}}}))
    assert load_servers(client)[0].name == "fs"

    assert len(load_servers(MANIFEST)) == 3


def test_rejects_an_unrecognised_manifest(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"nope": 1}))
    with pytest.raises(ValueError):
        load_servers(bad)


@pytest.mark.parametrize("name,description,expected", [
    ("delete_file", "Delete a file permanently", Effect.WRITE),
    ("send_email", "Send an email to a user", Effect.EGRESS),
    ("run_shell", "Execute a shell command", Effect.COMPUTE),
    ("list_tickets", "List open tickets", Effect.READ),
])
def test_effect_inference(name, description, expected):
    assert expected in infer_effects(McpTool(name=name, description=description))


# ======================================================================
# MCP-specific checks -- each must fire on the sample
# ======================================================================
@pytest.mark.parametrize("category", [
    "description_injection",      # helpdesk.escalate
    "tool_shadowing",             # read_file on two servers
    "omnibus_tool",               # analytics.query
    "irreversible_no_brake",      # filesystem.delete_file
    "plaintext_secret",           # analytics API key
    "unauthenticated_transport",  # analytics over http
    "unconstrained_schema",       # filesystem paths
    "payload_admitted",           # traversal, SSRF, file-reading SELECTs
])
def test_each_check_fires_on_the_sample(audit, category):
    assert category in _cats(audit)


def test_invisible_characters_in_a_description_are_caught(audit):
    hits = [f for f in audit.findings
            if f.category == "description_injection" and "invisible" in f.title]
    assert hits and hits[0].tool == "helpdesk.escalate"


def test_omnibus_requires_two_signals():
    """A well-scoped tool with one free-form arg must NOT be flagged, or the
    check becomes the false-positive machine it exists to avoid."""
    tidy = McpServer(name="s", tools=(McpTool(
        name="get_user", description="Fetch one user by id.",
        input_schema={"properties": {"user_id": {"type": "string",
                                                 "pattern": "^[0-9]{6}$"}}}),))
    assert not [f for f in mcp_findings([tidy]) if f.category == "omnibus_tool"]


def test_confirmation_argument_suppresses_the_destructive_finding():
    braked = McpServer(name="s", tools=(McpTool(
        name="delete_record", description="Delete a record.",
        input_schema={"properties": {"id": {"type": "string"},
                                     "confirm": {"type": "boolean"}}}),))
    assert not [f for f in mcp_findings([braked])
                if f.category == "irreversible_no_brake"]


def test_shadowing_needs_two_servers():
    solo = McpServer(name="a", tools=(McpTool(name="read_file"),))
    assert not [f for f in mcp_findings([solo]) if f.category == "tool_shadowing"]


# ======================================================================
# Noise control
# ======================================================================
def test_consolidation_collapses_the_payload_corpus(servers):
    policy, registry = synthesize_policy(servers), build_registry(servers)
    raw = (mcp_findings(servers) + static_findings(policy, registry)
           + probe_findings(policy, registry))
    merged = consolidate(raw)
    assert len(merged) < len(raw) / 2, "consolidation is not earning its place"
    # at most one payload finding per (tool, arg)
    keys = [(f.tool, f.arg) for f in merged if f.category == "payload_admitted"]
    assert len(keys) == len(set(keys))


def test_no_probe_skipped_noise_in_the_deliverable(audit):
    assert "probe_skipped" not in _cats(audit)


@pytest.mark.parametrize("pattern,expected", [
    ("^[A-Z]{2}-[0-9]{4}$", "AA-0000"),
    (r"^\d{3}$", "000"),
    ("^abc$", "abc"),
    ("^[^x]+$", None),           # must refuse rather than guess
])
def test_pattern_sampling(pattern, expected):
    assert sample_from_pattern(pattern) == expected


def test_fingerprints_are_stable_across_runs(servers):
    def run():
        p, r = synthesize_policy(servers), build_registry(servers)
        return [f.fingerprint for f in
                consolidate(mcp_findings(servers) + static_findings(p, r)
                            + probe_findings(p, r))]
    assert run() == run()


# ======================================================================
# The hardening deliverable
# ======================================================================
def test_hardened_policy_closes_the_critical_findings(servers, tmp_path):
    """The claim the audit makes to the customer, asserted."""
    path = write_hardened(servers, tmp_path / "hardened.yaml")
    hardened = load_policy(path)
    registry = build_registry(servers)
    after = consolidate(static_findings(hardened, registry)
                        + probe_findings(hardened, registry))
    criticals = [f for f in after if f.severity == "critical"]
    assert not criticals, [str(f) for f in criticals]

    # the only residual high is architectural, not a missed payload
    highs = [f for f in after if f.severity == "high"]
    assert all(f.category == "taint_laundering" for f in highs), [str(f) for f in highs]


def test_hardened_policy_is_loadable_and_regexes_compile(servers, tmp_path):
    path = write_hardened(servers, tmp_path / "h.yaml")
    policy = load_policy(path)
    assert policy.tool_names == {f"{s.name}.{t.name}"
                                 for s in servers for t in s.tools}


def test_hardened_placeholders_are_obvious(servers):
    """A generated policy that looks finished is more dangerous than one that
    obviously needs a human."""
    doc = harden(servers)
    blob = json.dumps(doc)
    assert "REPLACE_WITH" in blob or all(
        "command" not in a.lower()
        for e in doc["tools"]["allow"] for a in (e.get("args") or {}))


def test_egress_tools_become_declared_sinks(servers):
    doc = harden(servers)
    assert "analytics.export_report" in doc["data"]["egress"]["sinks"]
    assert doc["data"]["egress"]["block_pii"]


# ======================================================================
# Report
# ======================================================================
def test_report_contains_witnesses_and_remediation(audit, servers):
    md = render_markdown(audit, servers, client="Acme",
                         hardened_path="hardened-policy.yaml")
    assert "# Agent tool-surface audit — Acme" in md
    assert "**Reproduces with:**" in md
    assert "**Fix:**" in md
    assert "What to do first" in md
    for f in audit.findings[:3]:
        assert f.fingerprint in md


def test_report_handles_a_clean_surface():
    clean = McpServer(name="s", tools=(McpTool(
        name="get_status", description="Return service status.",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False}),))
    md = render_markdown(AuditReport(findings=[]), [clean])
    assert "No critical or high-severity findings" in md


# ======================================================================
# Effect inference: schema shape and annotations, not just tool names
# ======================================================================
def _tool(name="t", desc="", props=None, annotations=None):
    return McpTool(name=name, description=desc,
                   input_schema={"properties": props or {}},
                   annotations=annotations or {})


def test_schema_shape_infers_effects_without_any_keyword():
    """A name that gives nothing away is the case keyword inference misses."""
    inf = infer_effects_detailed(_tool(
        "sync_workspace", "Keeps the local workspace in step with the remote one.",
        {"path": {"type": "string"}, "content": {"type": "string"}}))
    assert Effect.WRITE in inf.effects
    assert any(s.startswith("schema:") for s in inf.sources)


@pytest.mark.parametrize("props,expected", [
    ({"url": {"type": "string"}}, Effect.NETWORK),
    ({"url": {"type": "string"}, "body": {"type": "string"}}, Effect.EGRESS),
    ({"endpoint": {"type": "string", "format": "uri"}}, Effect.NETWORK),
    ({"cmd": {"type": "string"}}, Effect.COMPUTE),
    ({"path": {"type": "string"}, "data": {"type": "string"}}, Effect.WRITE),
    ({"confirm": {"type": "boolean"}}, Effect.WRITE),
])
def test_schema_signals(props, expected):
    assert expected in infer_effects_detailed(_tool(props=props)).effects


def test_annotations_may_widen_the_effect_set():
    plain = _tool("process", "Processes the thing.")
    assert infer_effects(plain) == frozenset({Effect.READ})
    widened = infer_effects(_tool("process", "Processes the thing.",
                                  annotations={"destructiveHint": True,
                                               "openWorldHint": True}))
    assert {Effect.WRITE, Effect.NETWORK} <= widened


def test_annotations_can_never_narrow_the_effect_set():
    """The audited party asserting its own innocence must not downgrade it."""
    lying = _tool("delete_file", "Delete a file permanently.",
                  {"path": {"type": "string"}}, {"readOnlyHint": True})
    inf = infer_effects_detailed(lying)
    assert Effect.WRITE in inf.effects
    assert inf.contradictions and inf.contradictions[0][0] == "readOnlyHint"


def test_honest_read_only_tool_is_not_contradicted():
    """Negative control: the check must not fire on a truthful annotation."""
    honest = _tool("list_tickets", "List open tickets.",
                   {"status": {"type": "string", "enum": ["open", "closed"]}},
                   {"readOnlyHint": True})
    inf = infer_effects_detailed(honest)
    assert inf.effects == frozenset({Effect.READ})
    assert inf.contradictions == ()
    assert [f for f in mcp_findings([McpServer(name="hd", tools=(honest,))])
            if f.category == "annotation_contradicts_surface"] == []


def test_honest_destructive_annotation_is_not_contradicted():
    honest = _tool("delete_file", "Delete a file permanently.",
                   {"path": {"type": "string"}, "confirm": {"type": "boolean"}},
                   {"destructiveHint": True})
    assert infer_effects_detailed(honest).contradictions == ()


def test_contradiction_finding_names_both_signals(servers):
    [f] = [f for f in mcp_findings(servers)
           if f.category == "annotation_contradicts_surface"]
    assert f.severity == "high"
    assert f.tool == "filesystem.sync_workspace"
    assert "readOnlyHint" in f.witness and "schema:" in f.witness


def test_inference_sources_are_recorded_for_every_sample_tool(servers):
    for server in servers:
        for tool in server.tools:
            inf = infer_effects_detailed(tool)
            assert inf.effects
            # Either we can say why, or we fell back to the READ default.
            assert inf.sources or inf.effects == frozenset({Effect.READ})

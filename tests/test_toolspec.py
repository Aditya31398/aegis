"""Non-MCP tool surfaces: OpenAI, Anthropic, LangChain.

The claim this file defends is that supporting another stack is an *ingest*
problem: once a declaration is normalised, the same synthesis, probing and
hardening apply, and the same tool should produce the same findings whichever
dialect it was declared in.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.adapters.toolspec import (ToolSpecError, declared_by, is_hosted,
                                     load_tool_surface, provider_validates)
from aegis.conformance.cli import main as cli
from aegis.conformance.mcp_checks import mcp_findings
from aegis.conformance.provider_checks import provider_findings
from aegis.decision import Effect
from aegis.adapters.mcp import infer_effects

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "sample_openai_tools.json"

_PARAMS = {"type": "object",
           "properties": {"path": {"type": "string"}},
           "required": ["path"]}

DIALECTS = {
    "openai-chat": {"tools": [{"type": "function", "function": {
        "name": "read_file", "description": "Read a file.", "parameters": _PARAMS}}]},
    "openai-responses": [{"type": "function", "name": "read_file",
                          "description": "Read a file.", "parameters": _PARAMS}],
    "anthropic": {"tools": [{"name": "read_file", "description": "Read a file.",
                             "input_schema": _PARAMS}]},
    "langchain": [{"name": "read_file", "description": "Read a file.",
                   "args_schema": _PARAMS}],
}


def _write(tmp_path, doc, name="tools.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# ----------------------------------------------------------------------
# Ingest
# ----------------------------------------------------------------------
@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_every_dialect_normalises_to_the_same_tool(tmp_path, dialect):
    [surface] = load_tool_surface(_write(tmp_path, DIALECTS[dialect]))
    [tool] = surface.tools
    assert tool.name == "read_file"
    assert tool.properties == {"path": {"type": "string"}}
    assert tool.required == ("path",)
    assert Effect.READ in infer_effects(tool)


@pytest.mark.parametrize("dialect", sorted(DIALECTS))
def test_analysis_is_dialect_independent(tmp_path, dialect):
    """The same tool must be judged the same way however it was declared.
    Only the provider-specific check may differ."""
    [surface] = load_tool_surface(_write(tmp_path, DIALECTS[dialect]))
    cats = {f.category for f in mcp_findings([surface])}
    assert cats == {"unconstrained_schema"}


def test_surface_is_named_after_the_file(tmp_path):
    [surface] = load_tool_surface(_write(tmp_path, DIALECTS["anthropic"], "my_agent.json"))
    assert surface.name == "my-agent"
    [named] = load_tool_surface(_write(tmp_path, DIALECTS["anthropic"]), name="checkout")
    assert named.name == "checkout"


def test_dialect_is_recorded(tmp_path):
    for dialect, expected in [("openai-chat", "openai"), ("openai-responses", "openai"),
                              ("anthropic", "anthropic"), ("langchain", "langchain")]:
        [surface] = load_tool_surface(_write(tmp_path, DIALECTS[dialect]))
        assert declared_by(surface.tools[0]) == expected, dialect


@pytest.mark.parametrize("doc,fragment", [
    ({"tools": []}, "expected a list"),
    ({"nope": 1}, "expected a list"),
    ({"tools": ["not-an-object"]}, "must be objects"),
    ({"tools": [{"description": "no name, no type"}]}, "neither"),
    ({"tools": [{"type": "function", "function": {"parameters": {}}}]}, "without a name"),
    ({"tools": [{"name": "x", "parameters": "not-an-object"}]}, "must be an object"),
])
def test_unreadable_declarations_are_refused(tmp_path, doc, fragment):
    with pytest.raises(ToolSpecError, match=fragment):
        load_tool_surface(_write(tmp_path, doc))


def test_invalid_json_is_refused(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ToolSpecError, match="not valid JSON"):
        load_tool_surface(p)


# ----------------------------------------------------------------------
# Hosted tools: nothing to constrain, so the probe result means nothing
# ----------------------------------------------------------------------
@pytest.mark.parametrize("kind,expected", [
    ("web_search", Effect.EGRESS),
    ("code_interpreter", Effect.COMPUTE),
    ("computer_use_preview", Effect.NETWORK),
    ("bash", Effect.COMPUTE),
])
def test_hosted_tools_carry_their_effects(tmp_path, kind, expected):
    [surface] = load_tool_surface(_write(tmp_path, {"tools": [{"type": kind}]}))
    [tool] = surface.tools
    assert is_hosted(tool)
    assert expected in infer_effects(tool)


def test_unknown_hosted_type_is_not_treated_as_a_harmless_read(tmp_path):
    [surface] = load_tool_surface(_write(tmp_path, {"tools": [{"type": "future_tool_v2"}]}))
    [tool] = surface.tools
    assert is_hosted(tool)
    assert infer_effects(tool) != frozenset({Effect.READ})
    [f] = [f for f in provider_findings([surface])
           if f.category == "hosted_tool_unbounded"]
    assert "future_tool_v2" in f.witness


def test_hosted_tool_is_reported_once_not_twice(tmp_path):
    """`unconstrained_schema` would fire on a tool with no schema at all.
    That is the same fact `hosted_tool_unbounded` states better."""
    [surface] = load_tool_surface(_write(tmp_path, {"tools": [{"type": "web_search"}]}))
    cats = [f.category for f in mcp_findings([surface]) + provider_findings([surface])]
    assert cats.count("hosted_tool_unbounded") == 1
    assert "unconstrained_schema" not in cats


# ----------------------------------------------------------------------
# Provider-side validation
# ----------------------------------------------------------------------
def _strict_tool(strict, extra_ok=False):
    params = {"type": "object", "properties": {"q": {"type": "string"}}}
    if not extra_ok:
        params["additionalProperties"] = False
    fn = {"name": "lookup", "description": "Look something up.", "parameters": params}
    entry = {"type": "function", "function": fn}
    if strict is not None:
        entry["strict"] = strict
    return {"tools": [entry]}


def test_openai_without_strict_is_reported(tmp_path):
    [surface] = load_tool_surface(_write(tmp_path, _strict_tool(None)))
    assert [f.category for f in provider_findings([surface])] == \
        ["provider_validation_off"]


def test_strict_with_closed_schema_is_not_reported(tmp_path):
    """Negative control: the correct configuration must be silent."""
    [surface] = load_tool_surface(_write(tmp_path, _strict_tool(True)))
    assert provider_validates(surface.tools[0])
    assert provider_findings([surface]) == []


def test_strict_without_closed_schema_is_still_reported(tmp_path):
    """OpenAI only enforces strict mode when additionalProperties is false;
    strict: true alone is a claim the provider does not keep."""
    [surface] = load_tool_surface(_write(tmp_path, _strict_tool(True, extra_ok=True)))
    [f] = provider_findings([surface])
    assert f.category == "provider_validation_off"
    assert "not actually enforced" in f.detail


@pytest.mark.parametrize("dialect", ["anthropic", "langchain"])
def test_stacks_without_a_strictness_switch_are_never_flagged(tmp_path, dialect):
    """Negative control: absence of `strict` means nothing outside OpenAI, so
    reporting it there would be a false positive by construction."""
    [surface] = load_tool_surface(_write(tmp_path, DIALECTS[dialect]))
    assert [f for f in provider_findings([surface])
            if f.category == "provider_validation_off"] == []


# ----------------------------------------------------------------------
# End to end
# ----------------------------------------------------------------------
def test_cli_audits_the_openai_sample(tmp_path, capsys):
    out = tmp_path / "o"
    code = cli(["tools", "--schema", str(SAMPLE), "--out", str(out),
                "--fail-on", "critical"])
    capsys.readouterr()
    assert code == 1
    for name in ("audit-report.md", "audit-report.html", "audit.json",
                 "audit.sarif", "hardened-policy.yaml"):
        assert (out / name).exists(), name

    doc = json.loads((out / "audit.json").read_text(encoding="utf-8"))
    cats = {f["category"] for f in doc["findings"]}
    assert {"hosted_tool_unbounded", "provider_validation_off",
            "payload_admitted"} <= cats
    # The one well-formed tool in the sample is the negative control: strict,
    # closed schema, patterned arguments. It must not be a critical or high.
    invoice = [f for f in doc["findings"] if "send_invoice_email" in f["tool"]]
    assert all(f["severity"] not in ("critical", "high") for f in invoice)


def test_cli_rejects_an_unreadable_schema(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    assert cli(["tools", "--schema", str(bad), "--out", str(tmp_path / "o")]) == 2
    assert "error:" in capsys.readouterr().err

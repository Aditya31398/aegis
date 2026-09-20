"""Checks for non-MCP tool surfaces (OpenAI, Anthropic, LangChain).

Two things exist on those surfaces that MCP does not have, and both change
what the rest of the audit means:

* a **hosted tool** has no argument schema, so there is nothing to constrain
  and nothing to probe -- the probe engine will report it clean because it
  cannot reach it at all;
* **provider-side validation** is opt-in. OpenAI enforces a function's schema
  only under `strict: true`. Without it, a schema is a hint to the model
  rather than a gate in front of the handler, which is the difference between
  "the model is unlikely to send that" and "the model cannot send that".

Both are facts read straight off the declaration, so both are `confirmed`.
"""
from __future__ import annotations

from aegis.adapters.mcp import McpServer, infer_effects
from aegis.adapters.toolspec import declared_by, is_hosted, provider_validates

from .loopholes import Finding


def provider_findings(servers: list[McpServer]) -> list[Finding]:
    out: list[Finding] = []
    for server in servers:
        for tool in server.tools:
            q = f"{server.name}.{tool.name}"
            out += _hosted(q, tool)
            out += _validation(q, tool)
    return out


def _hosted(q: str, tool) -> list[Finding]:
    if not is_hosted(tool):
        return []
    kind = tool.annotations.get("hosted_type", "hosted")
    effects = sorted(e.value for e in infer_effects(tool))
    return [Finding(
        "hosted_tool_unbounded", "high",
        "hosted tool has no argument schema to constrain",
        f"'{kind}' is executed by the provider, not by your handler, and "
        f"declares no arguments. Nothing in a policy can narrow it, and the "
        f"payload probe cannot reach it, so a clean probe result says nothing "
        f"about this tool. Its effects ({', '.join(effects)}) are bounded only "
        f"by the provider's own limits and by whether you attach it at all",
        tool=q, witness=f'{{"type": "{kind}"}}')]


def _validation(q: str, tool) -> list[Finding]:
    if is_hosted(tool) or provider_validates(tool):
        return []
    # Only OpenAI has a strictness switch, so only there does its absence mean
    # "unvalidated". Saying this about an Anthropic or LangChain tool would be
    # a false positive by construction.
    if declared_by(tool) != "openai":
        return []
    strict = tool.annotations.get("strict")
    extra_ok = tool.input_schema.get("additionalProperties") is not False
    reason = ("strict mode is off" if strict is not True else
              "strict mode is on but additionalProperties is not false, so it "
              "is not actually enforced")
    return [Finding(
        "provider_validation_off", "medium",
        "the provider does not enforce this tool's schema",
        f"{reason}. The declared schema then constrains what the model is "
        f"asked for, not what your handler can receive"
        + (", and undeclared arguments pass through" if extra_ok else "")
        + ". Validate arguments in the handler, or set strict: true together "
          "with additionalProperties: false",
        tool=q, witness=f"strict={strict!r}")]

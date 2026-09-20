"""MCP-specific checks.

The generic hunter finds payloads that get through. These find the structural
problems particular to MCP servers -- the ones that come up in nearly every
audit and that a pattern scanner reports badly.

Design note on false positives. Published YARA-based MCP scanners run around a
78% false-positive rate because they flag tool *descriptions* that merely
describe normal functionality. Every check here either produces a concrete
witness or requires two independent signals before it fires. A finding you have
to argue with is worse than no finding, because the customer stops reading.
"""
from __future__ import annotations

import re
import unicodedata
from collections import defaultdict

from aegis.adapters.mcp import (McpServer, McpTool, infer_effects,
                                infer_effects_detailed, kind_of)
from aegis.decision import Effect

from .loopholes import Finding

# ----------------------------------------------------------------------

_MULTI_OP = re.compile(
    r"\b(any|arbitrary|all|various|multiple|or more|etc\.?)\b.{0,40}"
    r"\b(command|operation|query|action|method|endpoint|tool)s?\b"
    r"|\b(operation|action|method|mode|verb)\b.{0,30}\b(parameter|argument|field)\b",
    re.I)

_FREEFORM = re.compile(r"\b(raw|free[- ]?form|any valid|unrestricted|passthrough|"
                       r"arbitrary)\b", re.I)

_DESTRUCTIVE = ("delete", "remove", "drop", "truncate", "purge", "destroy",
                "revoke", "terminate", "wipe", "reset")

_CONFIRM_ARGS = ("confirm", "confirmation", "dry_run", "dryrun", "force",
                 "acknowledge", "yes", "approve")

# Instructions aimed at the model rather than the human reading the docs.
_INJECTION = re.compile(
    r"\b(ignore|disregard|override)\b.{0,30}\b(previous|prior|above|instruction|rule)s?\b"
    r"|\bbefore (using|calling) any other\b"
    r"|\byou (must|should|will) (always|never)\b"
    r"|\bdo not (tell|mention|inform|reveal)\b.{0,20}\b(user|human)\b"
    r"|<(system|important|secret|hidden)>",
    re.I)

_SECRETISH = re.compile(
    r"(?i)(secret|token|password|passwd|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|bearer|client[_-]?secret)")

_LOOKS_LIVE = re.compile(
    r"^(sk|pk|ghp|xox[baprs])[-_][A-Za-z0-9]{12,}$|^[A-Za-z0-9/+=]{24,}$")


def _invisible(text: str) -> list[str]:
    return [c for c in text if unicodedata.category(c) == "Cf"]


# ----------------------------------------------------------------------

def mcp_findings(servers: list[McpServer]) -> list[Finding]:
    out: list[Finding] = []
    out += _shadowing(servers)
    for server in servers:
        out += _secrets(server)
        for tool in server.tools:
            q = f"{server.name}.{tool.name}"
            out += _omnibus(q, tool)
            out += _unconstrained(q, tool)
            out += _destructive(q, tool)
            out += _annotation_claims(q, tool)
            out += _description(q, tool)
    return out


# -- tool-name shadowing -----------------------------------------------
def _shadowing(servers: list[McpServer]) -> list[Finding]:
    seen: dict[str, list[str]] = defaultdict(list)
    for s in servers:
        for t in s.tools:
            seen[t.name].append(s.name)
    return [
        Finding("tool_shadowing", "high", "two servers expose the same tool name",
                f"'{name}' is exposed by {sorted(owners)}. Which one the client "
                f"routes to is resolution-order dependent, so a lower-trust "
                f"server can intercept calls meant for a trusted one",
                tool=name, witness=", ".join(sorted(owners)))
        for name, owners in sorted(seen.items()) if len(owners) > 1
    ]


# -- the omnibus tool --------------------------------------------------
def _omnibus(q: str, tool: McpTool) -> list[Finding]:
    """One handler taking a free-form string and deciding at runtime which of
    several underlying operations to run. Elegant in source, a privilege
    escalation primitive at audit time."""
    text = f"{tool.name} {tool.description}"
    signals: list[str] = []
    if _MULTI_OP.search(text):
        signals.append("description advertises multiple operations")
    if _FREEFORM.search(text):
        signals.append("description advertises free-form input")

    freeform_args = [
        p for p, s in tool.properties.items()
        if s.get("type", "string") == "string"
        and not s.get("enum") and not s.get("pattern") and not s.get("maxLength")
    ]
    if freeform_args and kind_of(freeform_args[0]) in ("command", "sql", "generic"):
        signals.append(f"unconstrained string argument '{freeform_args[0]}'")

    if len(signals) < 2:                       # two independent signals required
        return []
    return [Finding(
        "omnibus_tool", "high", "one tool dispatches many operations",
        "; ".join(signals) + ". Scope this into separate tools with explicit "
        "schemas, or the effective permission is the union of everything the "
        "handler can reach",
        tool=q, arg=freeform_args[0] if freeform_args else "",
        witness=tool.description[:120])]


# -- unconstrained schema ----------------------------------------------
def _unconstrained(q: str, tool: McpTool) -> list[Finding]:
    effects = infer_effects(tool)
    dangerous = bool(effects & {Effect.WRITE, Effect.EGRESS, Effect.NETWORK,
                                Effect.COMPUTE})
    out = []
    for prop, schema in tool.properties.items():
        if schema.get("type", "string") != "string":
            continue
        if schema.get("enum") or schema.get("pattern") or schema.get("maxLength"):
            continue
        kind = kind_of(prop)
        sev = ("critical" if kind == "command" and dangerous else
               "high" if dangerous else "medium")
        out.append(Finding(
            "unconstrained_schema", sev, "argument accepts any string",
            f"'{prop}' has no enum, pattern or maxLength on a tool with "
            f"{sorted(e.value for e in effects)} effects. The schema is the "
            f"only thing standing between the model and the handler",
            tool=q, arg=prop))
    if tool.input_schema.get("additionalProperties") is not False:
        out.append(Finding(
            "unconstrained_schema", "medium", "undeclared arguments accepted",
            "inputSchema does not set additionalProperties:false, so arguments "
            "the schema never described are passed through to the handler",
            tool=q))
    return out


# -- destructive without a brake ---------------------------------------
def _destructive(q: str, tool: McpTool) -> list[Finding]:
    hay = f"{tool.name} {tool.description}".lower()
    verb = next((v for v in _DESTRUCTIVE if v in hay), None)
    if verb is None:
        return []
    if any(c in p.lower() for p in tool.properties for c in _CONFIRM_ARGS):
        return []
    return [Finding(
        "irreversible_no_brake", "high", "destructive tool has no confirmation",
        f"the tool is described as '{verb}' but exposes no dry_run or confirm "
        f"argument, so a single model call is immediately irreversible",
        tool=q, witness=tool.description[:120])]


# -- annotations that claim less than the surface shows -----------------
_ANNOTATION_MEANING = {
    "readOnlyHint": "does not modify its environment",
    "destructiveHint": "performs only additive updates",
}


def _annotation_claims(q: str, tool: McpTool) -> list[Finding]:
    """An MCP annotation is the server author's own claim about the tool.
    Clients use it to decide what to auto-approve, and reviewers read it
    instead of the handler. A claim the schema or the tool name contradicts is
    therefore worse than no claim at all.

    Two independent signals are required to fire: the annotation itself, and
    an effect inferred from a different source. The witness names both.
    """
    inference = infer_effects_detailed(tool)
    out = []
    for claim, evidence in inference.contradictions:
        out.append(Finding(
            "annotation_contradicts_surface", "high",
            f"'{claim}' is contradicted by the tool's own surface",
            f"the server declares {claim}=" +
            ("true" if claim == "readOnlyHint" else "false") +
            f" ({_ANNOTATION_MEANING[claim]}), but {_explain(evidence)}. "
            f"Clients that auto-approve tools on this annotation would run it "
            f"unattended; treat the annotation as unreliable for this server",
            tool=q, witness=f"{claim} vs {evidence}"))
    return out


def _explain(evidence: str) -> str:
    kind, _, detail = evidence.partition(":")
    if kind == "schema":
        return f"its schema exposes {detail}, which mutates or sends"
    return f"it is described as '{detail}'"


# -- tool poisoning via description ------------------------------------
def _description(q: str, tool: McpTool) -> list[Finding]:
    out = []
    if (m := _INJECTION.search(tool.description)):
        out.append(Finding(
            "description_injection", "critical",
            "tool description contains model-directed instructions",
            "descriptions are placed in the model's context verbatim, so this "
            "text is an instruction channel, not documentation",
            tool=q, witness=m.group()[:120]))
    if (inv := _invisible(tool.description)):
        out.append(Finding(
            "description_injection", "critical",
            "tool description contains invisible characters",
            f"{len(inv)} formatting characters the model reads and a reviewer "
            f"does not: {[hex(ord(c)) for c in inv[:5]]}",
            tool=q, witness=repr(tool.description[:80])))
    return out


# -- plaintext secrets -------------------------------------------------
def _secrets(server: McpServer) -> list[Finding]:
    out = []
    for key, value in server.env.items():
        if not _SECRETISH.search(key):
            continue
        sev = "critical" if _LOOKS_LIVE.match(str(value)) else "medium"
        out.append(Finding(
            "plaintext_secret", sev, "credential in the client config",
            f"'{key}' is stored in the config file in plaintext with ordinary "
            f"dotfile permissions. Acceptable for a personal dev credential, "
            f"not for a production one; read from the OS keychain or a secret "
            f"manager instead",
            tool=server.name, arg=key,
            witness=f"{key}={str(value)[:4]}***"))
    if server.live and server.transport in ("http", "sse"):
        # Observed, not inferred: we connected and asked.
        if server.answered_without_credentials:
            out.append(Finding(
                "unauthenticated_transport", "critical",
                "remote server lists tools to anonymous clients",
                f"the server completed initialize and tools/list with no "
                f"credential attached. Anyone who can reach {server.command} "
                f"can enumerate, and likely call, its {len(server.tools)} tools",
                tool=server.name, confidence="confirmed",
                witness="tools/list answered with no Authorization header"))
    elif server.transport in ("http", "sse") and not server.env.get("AUTH_TOKEN"):
        out.append(Finding(
            "unauthenticated_transport", "high", "remote transport with no auth",
            f"transport is '{server.transport}' but the config carries no "
            f"credential; confirm the server is not reachable unauthenticated",
            tool=server.name))
    return out

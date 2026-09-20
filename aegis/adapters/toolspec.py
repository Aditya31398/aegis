"""Tool schemas that are not MCP: OpenAI, Anthropic, LangChain.

The audit pipeline is shaped around a normalised surface (`McpServer` /
`McpTool`), not around MCP the protocol, so pointing it at another stack is an
ingest problem and nothing else. This module converts the declarations those
stacks use into that surface; synthesis, probing, hardening and reporting are
the same code afterwards.

Two things here are not mere translation:

* **Hosted tools.** `{"type": "web_search"}` or `{"type": "code_interpreter"}`
  has no argument schema at all. There is nothing to constrain, and the model
  still gets a network or execution channel. They are carried through with
  synthetic descriptions so effect inference sees them for what they are, and
  `provider_checks` reports them.
* **Provider-side validation.** OpenAI only enforces a function's schema when
  `strict: true` (which also requires `additionalProperties: false`). Without
  it the schema is a suggestion to the model, not a gate, which changes what
  an unconstrained argument means.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mcp import McpServer, McpTool

# A hosted tool is a capability with no declared arguments. The description is
# synthetic and exists so effect inference and the reader both see the channel;
# the annotations widen the inferred effects the same way an MCP server's own
# annotations would.
_HOSTED: dict[str, tuple[str, dict[str, Any]]] = {
    "web_search": ("Hosted web search: the query string leaves your environment "
                   "and reaches the provider's search backend, which fetches "
                   "arbitrary sites.",
                   {"openWorldHint": True, "aegisEffects": ["network", "egress"]}),
    "web_search_preview": ("Hosted web search (preview): the query string leaves "
                           "your environment.",
                           {"openWorldHint": True,
                            "aegisEffects": ["network", "egress"]}),
    "file_search": ("Hosted file search over uploaded documents: reads whatever "
                    "was attached to the vector store.",
                    {"readOnlyHint": True, "aegisEffects": ["read"]}),
    "code_interpreter": ("Hosted sandbox that executes model-written code.",
                         {"aegisEffects": ["compute", "write"]}),
    "bash": ("Hosted shell: executes model-written commands.",
             {"aegisEffects": ["compute", "write"]}),
    "computer": ("Computer use: the model drives a real desktop, so every "
                 "application on it is reachable.",
                 {"openWorldHint": True,
                  "aegisEffects": ["compute", "write", "network", "egress"]}),
    "computer_use_preview": ("Computer use (preview): the model drives a real "
                             "desktop.",
                             {"openWorldHint": True,
                              "aegisEffects": ["compute", "write", "network", "egress"]}),
    "text_editor": ("Hosted file editor: creates and rewrites files.",
                    {"aegisEffects": ["write"]}),
    "image_generation": ("Hosted image generation: the prompt leaves your "
                         "environment.",
                         {"openWorldHint": True,
                          "aegisEffects": ["network", "egress"]}),
    "mcp": ("Remote MCP server attached by the provider: its tool surface is "
            "not declared here and is not audited by this run.",
            {"openWorldHint": True,
             "aegisEffects": ["read", "write", "network", "egress", "compute"]}),
}

# An unrecognised hosted type is assumed broad rather than harmless: the
# provider defines what it can do, and a new one arriving with a name we have
# never seen is exactly when under-claiming would be most misleading.
_HOSTED_FALLBACK = ("Hosted provider tool with no declared argument schema; "
                    "its authority is whatever the provider grants it.",
                    {"openWorldHint": True,
                     "aegisEffects": ["read", "write", "network", "egress", "compute"]})


class ToolSpecError(ValueError):
    """A schema file we cannot read as a tool surface."""


def load_tool_surface(path: str | Path, *, name: str | None = None
                      ) -> list[McpServer]:
    """Read an OpenAI / Anthropic / LangChain tool declaration file.

    Accepts the shapes people actually have on disk: the `tools=[...]` array
    passed to an API, a dict with a `tools` key, or a LangChain dump.
    """
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ToolSpecError(f"{p}: not valid JSON: {exc}") from exc

    entries = _entries(raw, p)
    tools = [_tool_from(e, p) for e in entries]
    tools = [t for t in tools if t is not None]
    if not tools:
        raise ToolSpecError(f"{p}: no tool declarations found")
    return [McpServer(name=name or _surface_name(p), tools=tuple(tools),
                      transport="in-process")]


def _entries(raw: Any, p: Path) -> list[dict]:
    if isinstance(raw, list):
        candidates = raw
    elif isinstance(raw, dict):
        for key in ("tools", "functions", "toolkit"):
            if isinstance(raw.get(key), list):
                candidates = raw[key]
                break
        else:
            # A single tool declared on its own.
            candidates = [raw] if ("name" in raw or "type" in raw) else []
    else:
        raise ToolSpecError(f"{p}: expected a list of tools or an object with 'tools'")
    if not candidates:
        raise ToolSpecError(f"{p}: expected a list of tools or an object with 'tools'")
    bad = [c for c in candidates if not isinstance(c, dict)]
    if bad:
        raise ToolSpecError(f"{p}: tool entries must be objects, got {type(bad[0]).__name__}")
    return candidates


def _tool_from(entry: dict, p: Path) -> McpTool | None:
    kind = entry.get("type")

    # OpenAI chat/assistants: {"type": "function", "function": {...}}
    if kind == "function" and isinstance(entry.get("function"), dict):
        return _function_tool(entry["function"], provider="openai",
                              strict=entry["function"].get("strict",
                                                           entry.get("strict")))

    # OpenAI Responses: {"type": "function", "name": ..., "parameters": {...}}
    if kind == "function":
        return _function_tool(entry, provider="openai", strict=entry.get("strict"))

    if kind is None and "name" in entry:
        return _function_tool(entry, provider=_dialect(entry),
                              strict=entry.get("strict"))

    # Hosted / built-in tool: a capability with no declared arguments.
    if isinstance(kind, str):
        description, annotations = _HOSTED.get(
            kind, _HOSTED.get(kind.rstrip("_0123456789"), _HOSTED_FALLBACK))
        return McpTool(
            name=entry.get("name") or kind,
            description=description,
            input_schema={},
            annotations={**annotations, "hosted": True, "hosted_type": kind},
        )

    raise ToolSpecError(f"{p}: tool entry has neither 'name' nor 'type': {entry}")


def _dialect(entry: dict) -> str:
    """Which stack declared this. It decides whether the *absence* of a
    strictness flag means anything: OpenAI validates only under `strict: true`,
    while Anthropic and LangChain have no such switch, so reporting its
    absence there would be a false positive by construction."""
    if "input_schema" in entry:
        return "anthropic"
    if "args_schema" in entry or "args" in entry:
        return "langchain"
    if "parameters" in entry or "strict" in entry:
        return "openai"
    return "unknown"


def _function_tool(fn: dict, *, provider: str = "unknown",
                   strict: Any = None) -> McpTool:
    name = fn.get("name")
    if not name:
        raise ToolSpecError(f"function tool without a name: {fn}")
    # `parameters` (OpenAI), `input_schema` (Anthropic), `args_schema`/`args`
    # (LangChain, depending on how it was dumped).
    schema = (fn.get("parameters") or fn.get("input_schema")
              or fn.get("args_schema") or fn.get("args") or {})
    if not isinstance(schema, dict):
        raise ToolSpecError(f"{name}: argument schema must be an object")
    annotations: dict[str, Any] = {"provider": provider}
    if strict is not None:
        annotations["strict"] = bool(strict)
    return McpTool(name=str(name), description=str(fn.get("description") or ""),
                   input_schema=schema, annotations=annotations)


def _surface_name(p: Path) -> str:
    stem = p.stem.replace("_", "-")
    cleaned = "".join(c if c.isalnum() or c in "-" else "-" for c in stem).strip("-")
    return cleaned or "tools"


def is_hosted(tool: McpTool) -> bool:
    return bool(tool.annotations.get("hosted"))


def declared_by(tool: McpTool) -> str:
    return str(tool.annotations.get("provider", "unknown"))


def provider_validates(tool: McpTool) -> bool:
    """True only when the provider itself enforces the declared schema.

    OpenAI does that under `strict: true`, which also requires
    `additionalProperties: false`. Anything else means the schema constrains
    what the model is *asked* for, not what the handler can *receive*.
    """
    return (tool.annotations.get("strict") is True
            and tool.input_schema.get("additionalProperties") is False)

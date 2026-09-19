"""MCP adapter.

Turns somebody else's MCP server into something the hunter can point at.

The audit product works in three moves:

  1. INGEST    -- read a tools/list response or a client config and normalise it.
  2. SYNTHESISE -- derive an Aegis policy from the declared JSON Schemas. This
                  is what the server *currently* permits, expressed as policy.
                  Every schema field with no constraint becomes an open door
                  the probe engine can walk through.
  3. HARDEN    -- emit a tightened policy the customer can actually adopt.

That third step is the deliverable. A findings list tells someone they have a
problem; a policy file they can drop in tells them what to do about it, and is
the difference between a report and a thing worth paying for.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..decision import Classification, Effect
from ..policy import ArgConstraint, Budget, DataPolicy, Policy, SpawnPolicy, ToolRule


# ----------------------------------------------------------------------
# Normalised view of a server
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class McpTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    # MCP tool annotations (readOnlyHint, destructiveHint, ...) as published.
    # Carried through ingest; not yet used for inference.
    annotations: dict[str, Any] = field(default_factory=dict)

    @property
    def properties(self) -> dict[str, dict]:
        return self.input_schema.get("properties") or {}

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(self.input_schema.get("required") or ())


@dataclass(frozen=True)
class McpServer:
    name: str
    tools: tuple[McpTool, ...] = ()
    env: dict[str, str] = field(default_factory=dict)
    command: str = ""
    args: tuple[str, ...] = ()
    transport: str = "stdio"
    # Set only by live ingest (adapters/mcp_client.py).
    live: bool = False
    answered_without_credentials: bool = False


def load_servers(path: str | Path) -> list[McpServer]:
    """Accepts a tools/list response, a client config, or an audit bundle."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))

    if "mcpServers" in raw:                      # claude_desktop_config.json style
        return [
            McpServer(
                name=name,
                tools=tuple(_tool(t) for t in (cfg.get("tools") or [])),
                env=dict(cfg.get("env") or {}),
                command=cfg.get("command", ""),
                args=tuple(cfg.get("args") or ()),
                transport=cfg.get("transport", "stdio"),
            )
            for name, cfg in raw["mcpServers"].items()
        ]

    if "servers" in raw:                         # audit bundle
        return [
            McpServer(
                name=s.get("name", "server"),
                tools=tuple(_tool(t) for t in (s.get("tools") or [])),
                env=dict(s.get("env") or {}),
                command=s.get("command", ""),
                args=tuple(s.get("args") or ()),
                transport=s.get("transport", "stdio"),
                live=bool(s.get("live", False)),
                answered_without_credentials=bool(
                    s.get("answered_without_credentials", False)),
            )
            for s in raw["servers"]
        ]

    if "tools" in raw:                           # bare tools/list response
        return [McpServer(name=raw.get("name", "server"),
                          tools=tuple(_tool(t) for t in raw["tools"]))]

    raise ValueError("unrecognised manifest: expected mcpServers, servers or tools")


def _tool(t: dict[str, Any]) -> McpTool:
    return McpTool(
        name=t["name"],
        description=t.get("description", "") or "",
        input_schema=t.get("inputSchema") or t.get("input_schema") or {},
        annotations=dict(t.get("annotations") or {}),
    )


# ----------------------------------------------------------------------
# Effect inference
# ----------------------------------------------------------------------

_VERBS: tuple[tuple[Effect, tuple[str, ...]], ...] = (
    (Effect.WRITE, ("write", "create", "update", "delete", "remove", "drop",
                    "insert", "patch", "rename", "move", "upload", "commit",
                    "merge", "publish", "deploy", "set_", "put_")),
    (Effect.EGRESS, ("send", "post", "email", "notify", "share", "export",
                     "publish", "upload", "message", "webhook")),
    (Effect.NETWORK, ("fetch", "http", "request", "curl", "browse", "crawl",
                      "download", "api_")),
    (Effect.COMPUTE, ("exec", "run", "eval", "shell", "command", "script",
                      "sandbox", "compile")),
    (Effect.READ, ("read", "get", "list", "search", "query", "find", "show",
                   "describe", "fetch", "select", "view", "cat")),
)

_SENSITIVE = ("secret", "credential", "password", "token", "key", "customer",
              "user", "email", "personal", "pii", "payroll", "salary",
              "patient", "account", "ssn", "aadhaar")


def infer_effects(tool: McpTool) -> frozenset[Effect]:
    hay = f"{tool.name} {tool.description}".lower()
    found = {eff for eff, verbs in _VERBS if any(v in hay for v in verbs)}
    return frozenset(found or {Effect.READ})


def infer_classification(tool: McpTool) -> Classification:
    hay = f"{tool.name} {tool.description}".lower()
    if any(w in hay for w in ("secret", "credential", "password", "token", "key")):
        return Classification.RESTRICTED
    if any(w in hay for w in _SENSITIVE):
        return Classification.CONFIDENTIAL
    return Classification.INTERNAL


# ----------------------------------------------------------------------
# Schema -> constraint
# ----------------------------------------------------------------------

def constraint_from_schema(prop: dict[str, Any]) -> ArgConstraint:
    """Whatever the server actually declares. Often nothing."""
    return ArgConstraint(
        matches=prop.get("pattern") and _anchor(prop["pattern"]),
        one_of=tuple(prop["enum"]) if prop.get("enum") else None,
        max_len=prop.get("maxLength"),
        max_value=prop.get("maximum"),
    )


def _anchor(pattern: str) -> str:
    p = pattern
    if not p.startswith("^"):
        p = "^" + p
    if not p.endswith("$"):
        p = p + "$"
    return p


def synthesize_policy(servers: list[McpServer], *, name: str = "observed"
                      ) -> Policy:
    """The policy the servers currently enforce, as far as their schemas say."""
    tools: dict[str, ToolRule] = {}
    sinks: set[str] = set()

    for server in servers:
        for t in server.tools:
            qualified = f"{server.name}.{t.name}"
            args = {p: constraint_from_schema(s) for p, s in t.properties.items()}
            tools[qualified] = ToolRule(
                name=qualified, args=args, require_args=t.required,
                deny_extra_args=bool(t.input_schema.get(
                    "additionalProperties", True) is False),
            )
            if infer_effects(t) & {Effect.EGRESS, Effect.NETWORK, Effect.WRITE}:
                sinks.add(qualified)

    return Policy(
        name=name,
        tools=tools,
        effects=frozenset(Effect),
        # Deliberately generous: we are describing what the server allows,
        # not what we wish it allowed. Budget findings would be noise here.
        budget=Budget(usd=1e6, tokens=10**9, wall_clock_s=1e6, tool_calls=10**6),
        data=DataPolicy(
            max_classification=Classification.RESTRICTED,
            egress_sinks=frozenset(sinks),
            egress_max_classification=Classification.RESTRICTED,
            block_pii=frozenset(),
        ),
        spawn=SpawnPolicy(),
    )


def build_registry(servers: list[McpServer]):
    """A registry of inert doubles so the probe engine has something to decide
    against. Nothing here ever contacts the real server."""
    from ..registry import ToolRegistry
    reg = ToolRegistry()
    for server in servers:
        for t in server.tools:
            qualified = f"{server.name}.{t.name}"
            reg.register(
                qualified, _inert(qualified),
                effects=infer_effects(t),
                classification=infer_classification(t),
                description=t.description[:200],
            )
    return reg


def _inert(name: str):
    def _fn(**kwargs):
        raise RuntimeError(f"audit doubles are never executed ({name})")
    _fn.__name__ = name.replace(".", "_").replace("-", "_")
    return _fn


# ----------------------------------------------------------------------
# Hardening -- the deliverable
# ----------------------------------------------------------------------

_HARDENERS: dict[str, dict[str, Any]] = {
    "path": {"prefix": "/workspace/",
             "forbid_matches": r"(?i)\.\.|%2e|%2f|%00|\x00|[\x00-\x1f]|/\.ssh|/\.env|id_rsa",
             "max_len": 1024},
    "url": {"matches": r"^https://[a-z0-9.-]+\.example\.com/[\w/-]*$",
            "max_len": 2048},
    "sql": {"matches": r"(?is)^\s*select\b.*",
            "forbid_matches": (r"(?i)\b(drop|delete|update|insert|alter|truncate|grant|"
                               r"union|copy|merge|call|execute)\b|\b(into\s+outfile|into\s+dumpfile|"
                               r"load_file|lo_import|lo_export|pg_read_file|pg_ls_dir|"
                               r"pg_sleep|pg_shadow|pg_authid|dblink\w*|xp_cmdshell)\b|"
                               r";\s*\S|/\*|--\s"),
            "max_len": 4000},
    "command": {"one_of": ["REPLACE_WITH_EXPLICIT_ALLOWLIST"]},
    "content": {"max_len": 65536},
    "generic": {"max_len": 4096},
}

_KINDS = (
    ("command", ("command", "cmd", "shell", "script", "code", "exec")),
    ("path", ("path", "file", "filename", "directory", "dir", "dest", "src")),
    ("url", ("url", "uri", "endpoint", "host", "webhook", "link")),
    ("sql", ("sql", "query", "statement")),
    ("content", ("content", "body", "text", "message", "payload", "data")),
)


def kind_of(arg: str) -> str:
    low = arg.lower()
    for kind, needles in _KINDS:
        if any(n in low for n in needles):
            return kind
    return "generic"


def harden(servers: list[McpServer], *, name: str = "hardened") -> dict[str, Any]:
    """Emit a policy document that closes the open doors.

    Placeholders are shouted in caps on purpose. A generated policy that looks
    finished is more dangerous than one that obviously needs a human.
    """
    allow: list[dict[str, Any]] = []
    sinks: list[str] = []

    for server in servers:
        for t in server.tools:
            qualified = f"{server.name}.{t.name}"
            effects = infer_effects(t)
            args: dict[str, Any] = {}
            for prop, schema in t.properties.items():
                declared = constraint_from_schema(schema)
                base = dict(_HARDENERS[kind_of(prop)])
                # keep whatever the server already declared, it is tighter
                if declared.one_of:
                    base = {"one_of": list(declared.one_of)}
                if declared.matches:
                    base["matches"] = declared.matches
                if declared.max_len:
                    base["max_len"] = min(base.get("max_len", declared.max_len),
                                          declared.max_len)
                args[prop] = base

            entry: dict[str, Any] = {"name": qualified}
            if t.required:
                entry["require_args"] = list(t.required)
            if args:
                entry["args"] = args
            allow.append(entry)

            if effects & {Effect.EGRESS, Effect.NETWORK, Effect.WRITE}:
                sinks.append(qualified)

    return {
        "name": name,
        "version": 1,
        "tools": {"allow": allow},
        "budget": {"usd": 5.0, "tokens": 400000,
                   "wall_clock_s": 900, "tool_calls": 250},
        "data": {
            "max_classification": "confidential",
            "egress": {
                "sinks": sorted(sinks),
                "max_classification": "internal",
                "block_pii": ["email", "phone_in", "ssn", "aadhaar",
                              "credit_card", "api_key", "private_key"],
            },
        },
        "spawn": {"max_depth": 1, "max_fanout": 3, "max_descendants": 4,
                  "child_budget_fraction": 0.4, "allow_tools": []},
    }


def write_hardened(servers: list[McpServer], path: str | Path) -> Path:
    path = Path(path)
    path.write_text(
        "# Generated by aegis from the observed MCP manifest.\n"
        "# Every REPLACE_WITH_* placeholder needs a human decision before use.\n"
        "# Review the url pattern: it defaults to a placeholder host.\n\n"
        + yaml.safe_dump(harden(servers), sort_keys=False, width=100), encoding="utf-8")
    return path

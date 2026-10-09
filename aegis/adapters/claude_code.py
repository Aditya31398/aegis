"""Claude Code hook: an Aegis policy over Claude Code's own tools (Bash, Edit, Write, WebFetch...).

In `.claude/settings.json`:

    {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command",
        "command": "aegis hook --policy .claude/aegis.yaml --audit .claude/aegis-audit.jsonl"}]}]}}

Claude Code runs the command before every tool call, with the call on stdin (`tool_name`, `tool_input`). The
kernel decides it (`Kernel.decide`: the allowlist, argument constraints, the data guard on what would leave). A
refusal exits 2 with the reason on stderr, which Claude Code shows the model while it blocks the call. An
allowed call exits 0 and prints nothing: the hook never approves anything, Claude Code's own permission rules
still apply, so it can only take authority away.

Each call is a fresh process, so nothing is carried from one call to the next: budgets, rates and the taint
of untrusted input are not tracked here (the MCP gateway keeps them, for MCP tools). Built-in tools are
registered with the effects they have (`BUILTIN_EFFECTS`), MCP tools (`mcp__server__tool`) with the effects
their names imply, and the policy is ratified against them. If the policy can't be read, doesn't ratify, or the
input isn't a tool call, the call is refused: like every guard, this fails closed.

Exit codes here are Claude Code's, not the CLI's: 0 lets the call proceed, 2 blocks it.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable

from ..audit import AuditLog
from ..decision import Effect
from ..grant import Grant
from ..guards import Call
from ..kernel import Kernel
from ..policy import Policy
from ..registry import ToolRegistry
from .mcp import McpTool, infer_effects_detailed

ALLOW, BLOCK = 0, 2

# What each of Claude Code's tools can do. A file write is an outward effect (C2 asks that the policy screen it
# as an egress sink); a shell can do anything a program can.
BUILTIN_EFFECTS: dict[str, frozenset[Effect]] = {
    **{t: frozenset({Effect.READ}) for t in ("Read", "Glob", "Grep", "LS", "NotebookRead", "BashOutput",
                                              "TodoRead", "ListMcpResourcesTool", "ReadMcpResourceTool")},
    **{t: frozenset({Effect.WRITE}) for t in ("Edit", "MultiEdit", "Write", "NotebookEdit")},
    **{t: frozenset({Effect.COMPUTE, Effect.WRITE, Effect.NETWORK}) for t in ("Bash", "PowerShell", "KillShell")},
    **{t: frozenset({Effect.NETWORK}) for t in ("WebFetch", "WebSearch")},
    **{t: frozenset({Effect.SPAWN}) for t in ("Task", "Agent")},
    **{t: frozenset() for t in ("TodoWrite", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "Skill")},
}


def effects_of(tool: str) -> frozenset[Effect]:
    if tool in BUILTIN_EFFECTS:
        return BUILTIN_EFFECTS[tool]
    name = tool.split("__", 2)[-1] if tool.startswith("mcp__") else tool
    return infer_effects_detailed(McpTool(name=name)).effects


def _noop(**_: Any) -> None:
    """Never called: the hook only decides. Claude Code runs the tool itself."""


def kernel_for(policy: Policy, audit: AuditLog | None = None, constitution=None) -> Kernel:
    """A kernel whose registry holds every tool the policy names, with its effects, ratified."""
    from ..constitution import default_constitution
    reg = ToolRegistry()
    for name in sorted(policy.tool_names):
        reg.register(name, _noop, effects={e.value for e in effects_of(name)},
                     untrusted=Effect.NETWORK in effects_of(name))
    (constitution or default_constitution()).ratify(policy, reg)
    return Kernel(reg, audit=audit)


def decide(policy_loader: Callable[[], Policy], payload: dict, *, agent: str = "claude-code",
           audit_path: str | None = None) -> tuple[int, str]:
    """(exit code, message for stderr) for one PreToolUse payload."""
    tool = payload.get("tool_name") if isinstance(payload, dict) else None
    args = payload.get("tool_input") if isinstance(payload, dict) else None
    if not isinstance(tool, str) or not isinstance(args, dict):
        return BLOCK, "Aegis: the hook was not given a tool call (tool_name, tool_input); refusing."
    try:
        policy = policy_loader()
        kernel = kernel_for(policy, AuditLog(audit_path) if audit_path else None)
    except Exception as exc:                      # noqa: BLE001 -- a policy that can't be enforced refuses
        return BLOCK, f"Aegis: refusing {tool}: the policy can't be enforced ({exc})"
    from ..observe import register_context_provider
    session = payload.get("session_id")
    unregister = register_context_provider(
        lambda: {"run_id": f"claude-code:{session}" if session else None, "workflow": "claude-code",
                 "cwd": payload.get("cwd")})
    try:
        grant = Grant.root(policy, agent)
        call = Call(tool=tool, args=dict(args))
        verdict = kernel.decide(grant, call)
        kernel._log(grant, call, verdict)
    finally:
        unregister()
    if verdict.allowed:
        return ALLOW, ""
    return BLOCK, f"Refused by Aegis ({verdict.rule}): {verdict.reason}"


def main(policy_loader: Callable[[], Policy], *, agent: str = "claude-code", audit_path: str | None = None,
         stdin=None, stderr=None) -> int:
    stdin, stderr = stdin or sys.stdin, stderr or sys.stderr
    try:
        payload = json.loads(stdin.read() or "null")
    except ValueError:
        payload = None
    code, msg = decide(policy_loader, payload, agent=agent, audit_path=audit_path)
    if msg:
        print(msg, file=stderr)
    return code

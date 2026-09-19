"""Conformance scenario format.

A scenario is a sequence of attempted effects and the verdict each MUST get.
Tests assert on the stable `rule` id, so reworded error messages never break
the suite, but a rule that silently stops firing does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Step:
    kind: str                       # "invoke" | "spawn" | "revoke"
    agent: str = "root"             # which bound agent performs it
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    # spawn-only
    name: str = ""
    tools: tuple[str, ...] = ()
    budget_fraction: float = 0.5
    bind: str = ""                  # bind the resulting child to this alias
    repeat: int = 1
    # expectation
    expect: str = "allow"           # "allow" | "deny"
    rule: str | None = None         # required rule id when expect == deny


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    steps: tuple[Step, ...]
    policy: str | None = None       # per-case override
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Suite:
    name: str
    policy: str
    cases: tuple[Case, ...]
    source: str = ""


def _step(raw: dict[str, Any]) -> Step:
    if "invoke" in raw:
        body = raw["invoke"]
        kind, tool, args = "invoke", body["tool"], dict(body.get("args") or {})
        name, tools, bf, bind = "", (), 0.5, ""
    elif "spawn" in raw:
        body = raw["spawn"]
        kind, tool, args = "spawn", "agent.spawn", {}
        name = body["name"]
        tools = tuple(body.get("tools") or ())
        bf = float(body.get("budget_fraction", 0.5))
        bind = body.get("bind", name)
    elif "revoke" in raw:
        kind, tool, args = "revoke", "agent.revoke", {}
        name, tools, bf, bind = raw["revoke"], (), 0.5, ""
    else:
        raise ValueError(f"step must contain invoke/spawn/revoke: {raw}")

    expect = raw.get("expect", "allow")
    rule = raw.get("rule")
    if expect == "deny" and not rule:
        raise ValueError(f"deny step must pin a rule id: {raw}")
    return Step(kind=kind, agent=raw.get("agent", "root"), tool=tool, args=args,
                name=name, tools=tools, budget_fraction=bf, bind=bind,
                repeat=int(raw.get("repeat", 1)), expect=expect, rule=rule)


def load_suite(path: str | Path) -> Suite:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases = tuple(
        Case(
            id=c["id"],
            description=c.get("description", ""),
            steps=tuple(_step(s) for s in c["steps"]),
            policy=c.get("policy"),
            tags=tuple(c.get("tags", ())),
        )
        for c in raw["cases"]
    )
    ids = [c.id for c in cases]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"{path}: duplicate case ids {sorted(dupes)}")
    return Suite(name=raw["suite"], policy=raw["policy"], cases=cases,
                 source=str(path))

"""Verdict types. Everything the kernel decides is expressed here."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    """Side-effect class of a tool. Used for coarse-grained policy."""
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EGRESS = "egress"
    SPAWN = "spawn"
    COMPUTE = "compute"


class Classification(int, Enum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def parse(cls, v: Any) -> "Classification":
        if isinstance(v, cls):
            return v
        return cls[str(v).upper()]


@dataclass(frozen=True)
class Verdict:
    """The result of a guard or of the whole guard chain.

    `rule` is a stable machine-readable id (e.g. 'capability.not_granted').
    Conformance tests assert on `rule`, never on `reason` prose.
    """
    allowed: bool
    rule: str = "allow.default"
    reason: str = ""
    guard: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def allow(rule: str = "allow.default", guard: str = "", **details) -> "Verdict":
        return Verdict(True, rule, "", guard, details)

    @staticmethod
    def deny(rule: str, reason: str, guard: str = "", **details) -> "Verdict":
        return Verdict(False, rule, reason, guard, details)


class PolicyViolation(RuntimeError):
    """Raised instead of performing an effect. Never catchable into an allow."""

    def __init__(self, verdict: Verdict, tool: str, agent_id: str):
        self.verdict = verdict
        self.tool = tool
        self.agent_id = agent_id
        super().__init__(
            f"[{verdict.rule}] agent={agent_id} tool={tool}: {verdict.reason}"
        )


class BudgetExhausted(PolicyViolation):
    pass

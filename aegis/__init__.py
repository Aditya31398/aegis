"""Aegis -- capability-based constraint enforcement for agent systems."""
from .audit import AuditLog, AuditRecord
from .decision import (BudgetExhausted, Classification, Effect, PolicyViolation,
                       Verdict)
from .grant import Budget, BudgetLedger, Grant, SpawnRequest
from .guards import Call
from .kernel import Kernel, build_kernel
from .policy import Policy, PolicyError, load_policy, parse_policy
from .registry import ToolRegistry, ToolSpec
from .runtime import Agent, Toolbox, ToolProxy

__version__ = "0.1.0"

__all__ = [
    "Agent", "AuditLog", "AuditRecord", "Budget", "BudgetLedger",
    "BudgetExhausted", "Call", "Classification", "Effect", "Grant", "Kernel",
    "Policy", "PolicyError", "PolicyViolation", "SpawnRequest", "ToolProxy",
    "Toolbox", "ToolRegistry", "ToolSpec", "Verdict", "build_kernel",
    "load_policy", "parse_policy",
]

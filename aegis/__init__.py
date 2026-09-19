"""Aegis -- capability-based constraint enforcement for agent systems."""
from .audit import AuditLog, AuditRecord
from .decision import (BudgetExhausted, Classification, Effect, PolicyViolation,
                       Verdict)
from .grant import Budget, BudgetLedger, Grant, SpawnRequest
from .guards import Call
from .kernel import Kernel, build_kernel
from .policy import Policy, PolicyError, load_policy, parse_policy
from .registry import ToolRegistry, ToolSpec
from .runtime import Agent, AsyncToolbox, AsyncToolProxy, Toolbox, ToolProxy

__version__ = "0.2.0"

__all__ = [
    "Agent", "AsyncToolbox", "AsyncToolProxy", "AuditLog", "AuditRecord", "Budget", "BudgetLedger",
    "BudgetExhausted", "Call", "Classification", "Effect", "Grant", "Kernel",
    "Policy", "PolicyError", "PolicyViolation", "SpawnRequest", "ToolProxy",
    "Toolbox", "ToolRegistry", "ToolSpec", "Verdict", "build_kernel",
    "load_policy", "parse_policy",
]

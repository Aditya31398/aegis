"""The constitution: law above the policies.

A policy (`policies/*.yaml`) is a statute -- it grants and restricts, it can be
amended, and a widening amendment can be waived by a reviewer.

A constitutional clause cannot. It is a structural property every policy must
satisfy to be *ratified*, and the kernel refuses to start on an unratified
policy. There is deliberately no `--waive` path: the only way past a clause is
to edit `constitution.yaml`, which shows up as a loud, reviewable diff rather
than a flag buried in a CI invocation.

Clauses are checked against the policy AND the registry together, because most
real holes live in the gap between them -- a tool whose declared effects the
policy never accounted for.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from .decision import Classification, Effect
from .policy import Policy
from .registry import ToolRegistry


@dataclass(frozen=True)
class ClauseViolation:
    clause: str
    title: str
    detail: str
    severity: str = "critical"

    def __str__(self) -> str:
        return f"[{self.clause}] {self.title}: {self.detail}"


class UnconstitutionalPolicy(Exception):
    def __init__(self, violations: list[ClauseViolation]):
        self.violations = violations
        super().__init__("policy fails ratification:\n  " +
                         "\n  ".join(str(v) for v in violations))


# ----------------------------------------------------------------------
# Clause implementations. Each returns a list of violations.
# ----------------------------------------------------------------------
_CLAUSES: dict[str, Callable] = {}


def clause(cid: str):
    def deco(fn):
        _CLAUSES[cid] = fn
        return fn
    return deco


@clause("C1")
def _bounded_authority(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """No agent may hold unbounded authority on any budget axis."""
    out = []
    for axis in ("usd", "tokens", "wall_clock_s", "tool_calls"):
        v = getattr(p.budget, axis)
        if v <= 0:
            out.append(ClauseViolation(
                "C1", "unbounded authority",
                f"budget.{axis} is {v}; every axis must be positive and finite"))
    return out


@clause("C2")
def _every_egress_is_screened(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """Any tool that can move data outward must be a declared egress sink."""
    if reg is None:
        return []
    out = []
    for name in sorted(p.tool_names):
        spec = reg.spec(name)
        if spec is None:
            continue
        outward = spec.effects & {Effect.EGRESS, Effect.NETWORK, Effect.WRITE}
        if outward and name not in p.data.egress_sinks:
            out.append(ClauseViolation(
                "C2", "unscreened egress path",
                f"'{name}' declares {sorted(e.value for e in outward)} but is "
                f"not in data.egress.sinks, so nothing screens what leaves "
                f"through it"))
    if p.data.egress_sinks and not p.data.block_pii:
        out.append(ClauseViolation(
            "C2", "unscreened egress path",
            "egress sinks are declared but block_pii is empty"))
    return out


@clause("C3")
def _no_unconstrained_dangerous_arg(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """Arguments to effectful tools must carry at least one constraint."""
    if reg is None:
        return []
    out = []
    dangerous = {Effect.WRITE, Effect.NETWORK, Effect.EGRESS}
    for name, rule in sorted(p.tools.items()):
        spec = reg.spec(name)
        if spec is None or not (spec.effects & dangerous):
            continue
        if not rule.args:
            out.append(ClauseViolation(
                "C3", "unconstrained effectful tool",
                f"'{name}' has side effects but declares no argument constraints"))
            continue
        for arg in rule.require_args:
            if arg not in rule.args:
                out.append(ClauseViolation(
                    "C3", "unconstrained argument",
                    f"'{name}.{arg}' is required but accepts any value"))
    return out


@clause("C4")
def _delegation_strictly_attenuates(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """A child must be strictly weaker than its parent, and depth bounded."""
    out = []
    sp = p.spawn
    if sp.max_depth > 0:
        if sp.child_budget_fraction >= 1.0:
            out.append(ClauseViolation(
                "C4", "non-attenuating delegation",
                f"child_budget_fraction is {sp.child_budget_fraction}; a child "
                f"must receive strictly less than the parent's remainder"))
        if sp.max_depth > int(cfg.get("max_permitted_depth", 4)):
            out.append(ClauseViolation(
                "C4", "unbounded delegation",
                f"max_depth {sp.max_depth} exceeds the constitutional ceiling "
                f"{cfg.get('max_permitted_depth', 4)}"))
        if sp.max_fanout <= 0 or sp.max_descendants <= 0:
            out.append(ClauseViolation(
                "C4", "unbounded delegation",
                "spawn is permitted but max_fanout/max_descendants are not set"))
    return out


@clause("C5")
def _reading_is_not_exporting(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """Authority to read sensitive data never implies authority to export it."""
    if int(p.data.egress_max_classification) >= int(p.data.max_classification) \
            and int(p.data.max_classification) > int(Classification.PUBLIC):
        return [ClauseViolation(
            "C5", "read implies export",
            f"read ceiling {p.data.max_classification.name} is not above the "
            f"egress ceiling {p.data.egress_max_classification.name}; anything "
            f"readable is exportable")]
    return []


@clause("C6")
def _pii_rules_are_enforceable(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """A PII kind with no detector is a rule that silently never fires."""
    from .guards.data import _PATTERNS
    known = set(_PATTERNS) | {"credit_card"}
    unknown = sorted(p.data.block_pii - known)
    if unknown:
        return [ClauseViolation(
            "C6", "unenforceable rule",
            f"block_pii names {unknown}, for which no detector exists; these "
            f"rules read as protection but never fire")]
    return []


@clause("C7")
def _granted_tools_exist(p: Policy, reg: ToolRegistry | None, cfg: dict):
    """A grant for a tool that is not registered is a latent hole."""
    if reg is None:
        return []
    missing = sorted(p.tool_names - reg.names() - {"agent.spawn"})
    if missing:
        return [ClauseViolation(
            "C7", "phantom grant",
            f"policy grants {missing}, which no registered tool implements; a "
            f"later registration silently activates them", severity="high")]
    return []


# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Constitution:
    version: int
    clauses: dict[str, dict]
    source: str = ""

    @staticmethod
    def load(path: str | Path) -> "Constitution":
        raw = yaml.safe_load(Path(path).read_text())
        return Constitution(version=int(raw.get("version", 1)),
                            clauses={c["id"]: c for c in raw["clauses"]},
                            source=str(path))

    def review(self, policy: Policy,
               registry: ToolRegistry | None = None) -> list[ClauseViolation]:
        out: list[ClauseViolation] = []
        for cid, cfg in sorted(self.clauses.items()):
            if not cfg.get("enabled", True):
                continue
            fn = _CLAUSES.get(cid)
            if fn is None:
                out.append(ClauseViolation(
                    cid, "unimplemented clause",
                    f"constitution declares {cid} but no check implements it"))
                continue
            out.extend(fn(policy, registry, cfg.get("config", {})))
        return out

    def ratify(self, policy: Policy,
               registry: ToolRegistry | None = None) -> None:
        violations = self.review(policy, registry)
        if violations:
            raise UnconstitutionalPolicy(violations)


DEFAULT_CONSTITUTION = Path(__file__).resolve().parents[1] / "constitution.yaml"


def default_constitution() -> Constitution:
    return Constitution.load(DEFAULT_CONSTITUTION)

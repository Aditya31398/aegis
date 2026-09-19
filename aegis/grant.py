"""Capability grants.

A Grant is the *only* thing that authorises an effect. It is immutable and can
only ever be attenuated, never widened -- `Grant.attenuate()` raises if the
request asks for anything the parent does not already hold. This is what makes
"a spawned agent can never do more than its parent" a structural property
rather than a convention.

Budgets are hierarchical: a child's spend debits every ancestor's ledger too,
so a swarm of children cannot collectively outspend the root.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from .decision import Verdict
from .policy import Budget, Policy, PolicyError


class BudgetLedger:
    """Thread-safe, hierarchical spend tracker. Charges are all-or-nothing."""

    def __init__(self, limit: Budget, parent: "BudgetLedger | None" = None):
        self.limit = limit
        self.parent = parent
        self._lock = threading.RLock()
        self.usd = 0.0
        self.tokens = 0
        self.tool_calls = 0
        self.started = time.monotonic()

    # -- introspection ---------------------------------------------------
    @property
    def elapsed_s(self) -> float:
        return time.monotonic() - self.started

    def remaining(self) -> Budget:
        return Budget(
            usd=max(0.0, self.limit.usd - self.usd),
            tokens=max(0, self.limit.tokens - self.tokens),
            wall_clock_s=max(0.0, self.limit.wall_clock_s - self.elapsed_s),
            tool_calls=max(0, self.limit.tool_calls - self.tool_calls),
        )

    def chain(self) -> list["BudgetLedger"]:
        node, out = self, []
        while node is not None:
            out.append(node)
            node = node.parent
        return out

    # -- enforcement -----------------------------------------------------
    def check(self, usd: float = 0.0, tokens: int = 0, calls: int = 1) -> Verdict:
        for node in self.chain():
            if node.usd + usd > node.limit.usd:
                return Verdict.deny("budget.usd_exceeded",
                                    f"spend {node.usd + usd:.4f} > limit {node.limit.usd}",
                                    "budget")
            if node.tokens + tokens > node.limit.tokens:
                return Verdict.deny("budget.tokens_exceeded",
                                    f"tokens {node.tokens + tokens} > limit {node.limit.tokens}",
                                    "budget")
            if node.tool_calls + calls > node.limit.tool_calls:
                return Verdict.deny("budget.tool_calls_exceeded",
                                    f"calls {node.tool_calls + calls} > limit {node.limit.tool_calls}",
                                    "budget")
            if node.elapsed_s > node.limit.wall_clock_s:
                return Verdict.deny("budget.deadline_exceeded",
                                    f"elapsed {node.elapsed_s:.1f}s > {node.limit.wall_clock_s}s",
                                    "budget")
        return Verdict.allow("budget.ok", "budget")

    def charge(self, usd: float = 0.0, tokens: int = 0, calls: int = 1) -> Verdict:
        with self._lock:
            v = self.check(usd, tokens, calls)
            if not v.allowed:
                return v
            for node in self.chain():
                node.usd += usd
                node.tokens += tokens
                node.tool_calls += calls
            return v

    def refund(self, usd: float = 0.0, tokens: int = 0, calls: int = 0) -> None:
        with self._lock:
            for node in self.chain():
                node.usd -= usd
                node.tokens -= tokens
                node.tool_calls -= calls


@dataclass(frozen=True)
class SpawnRequest:
    """What a parent asks for when creating a child."""
    name: str
    tools: frozenset[str]
    budget_fraction: float = 0.5
    role: str = "worker"


@dataclass
class Grant:
    """Immutable-by-convention authority token. Mutated only by the kernel."""
    grant_id: str
    agent_name: str
    policy: Policy
    ledger: BudgetLedger
    depth: int = 0
    parent: "Grant | None" = None
    children: list["Grant"] = field(default_factory=list)
    revoked: bool = False
    # Data-flow taint: highest classification this agent has observed.
    taint: int = 0

    # -- construction ----------------------------------------------------
    @staticmethod
    def root(policy: Policy, agent_name: str = "root") -> "Grant":
        return Grant(
            grant_id=f"g-{uuid.uuid4().hex[:12]}",
            agent_name=agent_name,
            policy=policy,
            ledger=BudgetLedger(policy.budget),
        )

    # -- topology --------------------------------------------------------
    def descendants(self) -> list["Grant"]:
        out = []
        for c in self.children:
            out.append(c)
            out.extend(c.descendants())
        return out

    def root_grant(self) -> "Grant":
        node = self
        while node.parent is not None:
            node = node.parent
        return node

    def is_active(self) -> bool:
        node = self
        while node is not None:
            if node.revoked:
                return False
            node = node.parent
        return True

    def revoke(self) -> None:
        """Revoking a grant revokes its whole subtree, immediately."""
        self.revoked = True
        for c in self.children:
            c.revoke()

    # -- attenuation -----------------------------------------------------
    def attenuate(self, req: SpawnRequest) -> "Grant":
        """Derive a strictly weaker child grant, or raise PolicyError.

        INVARIANT (verified by aegis/conformance/invariants.py):
            child.tools ⊆ parent.tools
            child.budget ≤ parent.remaining * fraction
            child.depth  = parent.depth + 1
            every constraint on a shared tool is >= as strict as the parent's
        """
        sp = self.policy.spawn

        widened = req.tools - self.policy.tool_names
        if widened:
            raise PolicyError(
                f"spawn.privilege_escalation: child requested {sorted(widened)} "
                f"not held by parent '{self.agent_name}'")

        if sp.allow_tools is not None:
            forbidden = req.tools - sp.allow_tools
            if forbidden:
                raise PolicyError(
                    f"spawn.tool_not_delegable: {sorted(forbidden)} may not be "
                    f"delegated to children under policy '{self.policy.name}'")

        frac = min(req.budget_fraction, sp.child_budget_fraction)
        child_limit = self.ledger.remaining().scaled(frac)

        child_policy = self.policy.restricted_to(set(req.tools))
        # A child never gets deeper spawn authority than remains to it.
        child_policy = _shrink_spawn(child_policy, child_limit, self.depth + 1)

        child = Grant(
            grant_id=f"g-{uuid.uuid4().hex[:12]}",
            agent_name=req.name,
            policy=child_policy,
            ledger=BudgetLedger(child_limit, parent=self.ledger),
            depth=self.depth + 1,
            parent=self,
            taint=self.taint,
        )
        self.children.append(child)
        return child


def _shrink_spawn(policy: Policy, limit, depth: int) -> Policy:
    from dataclasses import replace
    sp = policy.spawn
    return replace(
        policy,
        budget=limit,
        spawn=replace(sp, max_depth=max(0, sp.max_depth)),
    )

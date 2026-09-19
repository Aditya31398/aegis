"""Invariants: properties that must hold for *every* execution, not just the
scenarios someone thought to write down.

A random workload generator drives the kernel with thousands of arbitrary
call/spawn sequences and each invariant is checked after every operation. This
is the part that catches regressions nobody anticipated.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from aegis.decision import PolicyViolation
from aegis.grant import Grant, SpawnRequest
from aegis.kernel import Kernel
from aegis.policy import Policy

from .fixtures import SideEffectRecorder, build_fixture_registry


@dataclass
class Violation:
    invariant: str
    detail: str


# ----------------------------------------------------------------------
# Invariants
# ----------------------------------------------------------------------

def inv_attenuation(root: Grant, **_) -> list[Violation]:
    """No grant anywhere in the tree holds a capability its parent lacks."""
    out = []
    for g in root.descendants():
        extra = g.policy.tool_names - g.parent.policy.tool_names
        if extra:
            out.append(Violation("attenuation",
                                 f"{g.agent_name} holds {sorted(extra)} "
                                 f"not held by {g.parent.agent_name}"))
    return out


def inv_depth_bound(root: Grant, **_) -> list[Violation]:
    cap = root.policy.spawn.max_depth
    return [Violation("depth_bound", f"{g.agent_name} at depth {g.depth} > {cap}")
            for g in root.descendants() if g.depth > cap]


def inv_budget_conservation(root: Grant, **_) -> list[Violation]:
    """Total spend across the whole tree never exceeds the root's limit."""
    out = []
    led = root.ledger
    if led.usd > led.limit.usd + 1e-9:
        out.append(Violation("budget_conservation",
                             f"root usd {led.usd} > limit {led.limit.usd}"))
    if led.tool_calls > led.limit.tool_calls:
        out.append(Violation("budget_conservation",
                             f"root calls {led.tool_calls} > {led.limit.tool_calls}"))
    for g in root.descendants():
        if not g.ledger.limit.le(g.parent.ledger.limit):
            out.append(Violation("budget_conservation",
                                 f"{g.agent_name} limit exceeds parent's"))
    return out


def inv_no_effect_on_deny(root: Grant, *, kernel: Kernel,
                          recorder: SideEffectRecorder, **_) -> list[Violation]:
    """Executed side effects must never exceed the number of ALLOW records for
    executable tools. A denial that still ran code shows up here."""
    allows = sum(1 for r in kernel.audit.records
                 if r.allowed and r.tool not in ("agent.spawn", "agent.revoke"))
    if len(recorder.calls) > allows:
        return [Violation("no_effect_on_deny",
                          f"{len(recorder.calls)} executions vs {allows} allows")]
    return []


def inv_audit_chain(root: Grant, *, kernel: Kernel, **_) -> list[Violation]:
    return ([] if kernel.audit.verify()
            else [Violation("audit_chain", "hash chain does not verify")])


def inv_revocation_is_total(root: Grant, **_) -> list[Violation]:
    """If a grant is revoked, nothing under it can still be active."""
    out = []
    for g in [root, *root.descendants()]:
        if g.revoked:
            live = [d.agent_name for d in g.descendants() if d.is_active()]
            if live:
                out.append(Violation("revocation_is_total",
                                     f"{g.agent_name} revoked but {live} active"))
    return out


INVARIANTS: tuple[Callable, ...] = (
    inv_attenuation, inv_depth_bound, inv_budget_conservation,
    inv_no_effect_on_deny, inv_audit_chain, inv_revocation_is_total,
)


# ----------------------------------------------------------------------
# Random workload
# ----------------------------------------------------------------------

_HOSTILE_ARGS = [
    {"path": "/etc/passwd"},
    {"path": "/workspace/../../root/.ssh/id_rsa"},
    {"url": "https://evil.example.com/collect"},
    {"sql": "DROP TABLE users"},
    {"sql": "SELECT * FROM users"},
    {"url": "https://api.internal.corp/v1/items", "body": "card 4111111111111111"},
    {"query": "x" * 5000},
    {},
]


def fuzz(policy: Policy, *, steps: int = 400, seed: int = 0
         ) -> list[Violation]:
    rng = random.Random(seed)
    registry, recorder = build_fixture_registry(policy)
    kernel = Kernel(registry)
    root = Grant.root(policy, "root")
    live: list[Grant] = [root]
    violations: list[Violation] = []

    tools = sorted(policy.tool_names | {"shell.exec", "payments.transfer",
                                        "iam.grant", "email.send"})

    for i in range(steps):
        grant = rng.choice(live)
        roll = rng.random()
        try:
            if roll < 0.25:
                req = SpawnRequest(
                    name=f"a{i}",
                    tools=frozenset(rng.sample(tools, rng.randint(0, min(3, len(tools))))),
                    budget_fraction=rng.choice([0.1, 0.5, 0.9, 1.0, 2.0]))
                live.append(kernel.spawn(grant, req))
            elif roll < 0.30 and len(live) > 1:
                kernel.revoke(rng.choice(live[1:]))
            else:
                kernel.invoke(grant, rng.choice(tools), **rng.choice(_HOSTILE_ARGS))
        except PolicyViolation:
            pass                      # denial is a valid outcome
        except Exception as exc:      # anything else is a framework bug
            violations.append(Violation("kernel_crash", f"{type(exc).__name__}: {exc}"))

        for inv in INVARIANTS:
            violations.extend(inv(root, kernel=kernel, recorder=recorder))
        if violations:
            break
    return violations

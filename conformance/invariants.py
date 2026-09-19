"""Invariants: properties that must hold for *every* execution, not just the
scenarios someone thought to write down.

A random workload generator drives the kernel with thousands of arbitrary
call/spawn sequences and each invariant is checked after every operation. This
is the part that catches regressions nobody anticipated.

`afuzz` runs the same invariants against the async path: each round is a batch
of operations launched together under `asyncio.gather`, some cancelled
mid-flight, with a watcher task re-checking every invariant at each yield
point. Sequential fuzzing can only observe the kernel between calls; this
observes it *during* them.
"""
from __future__ import annotations

import asyncio
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


def inv_every_effect_was_charged(root: Grant, *, recorder: SideEffectRecorder,
                                 **_) -> list[Violation]:
    """Every execution was paid for. The root ledger sees every charge in the
    tree, so executions can never outnumber charged calls."""
    if len(recorder.calls) > root.ledger.tool_calls:
        return [Violation("every_effect_was_charged",
                          f"{len(recorder.calls)} executions vs "
                          f"{root.ledger.tool_calls} charged calls")]
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
    inv_no_effect_on_deny, inv_every_effect_was_charged, inv_audit_chain,
    inv_revocation_is_total,
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

# Well-formed calls the base policy admits, paired with their tool. Without
# these almost every call is denied at the guards, budgets are never exhausted,
# and the budget invariants are checked against a ledger that barely moves --
# the fuzzer looks green because it never reaches the interesting state.
_BENIGN_CALLS = [
    ("kb.search", {"query": "quarterly report"}),
    ("fs.read", {"path": "/workspace/notes.txt"}),
    ("http.get", {"url": "https://api.internal.corp/v1/items"}),
    ("db.query", {"sql": "SELECT id FROM orders"}),
]


def _pick_call(rng: random.Random, tools: list[str]) -> tuple[str, dict]:
    if rng.random() < 0.5:
        tool, args = rng.choice(_BENIGN_CALLS)
        return tool, dict(args)
    return rng.choice(tools), dict(rng.choice(_HOSTILE_ARGS))


def _pick_grant(rng: random.Random, live: list[Grant]) -> Grant:
    """Mostly active grants, so work actually happens; sometimes a revoked
    one, so revocation keeps being exercised."""
    active = [g for g in live if g.is_active()]
    if active and rng.random() < 0.85:
        return rng.choice(active)
    return rng.choice(live)


_OFF_POLICY = {"shell.exec", "payments.transfer", "iam.grant", "email.send"}


def _check_all(root: Grant, kernel: Kernel, recorder: SideEffectRecorder
               ) -> list[Violation]:
    out: list[Violation] = []
    for inv in INVARIANTS:
        out.extend(inv(root, kernel=kernel, recorder=recorder))
    return out


def fuzz(policy: Policy, *, steps: int = 400, seed: int = 0
         ) -> list[Violation]:
    rng = random.Random(seed)
    registry, recorder = build_fixture_registry(policy)
    kernel = Kernel(registry)
    root = Grant.root(policy, "root")
    live: list[Grant] = [root]
    violations: list[Violation] = []

    tools = sorted(policy.tool_names | _OFF_POLICY)

    for i in range(steps):
        grant = _pick_grant(rng, live)
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
                tool, args = _pick_call(rng, tools)
                kernel.invoke(grant, tool, **args)
        except PolicyViolation:
            pass                      # denial is a valid outcome
        except Exception as exc:      # anything else is a framework bug
            violations.append(Violation("kernel_crash", f"{type(exc).__name__}: {exc}"))

        violations.extend(_check_all(root, kernel, recorder))
        if violations:
            break
    return violations


def afuzz(policy: Policy, *, rounds: int = 60, batch: int = 12, seed: int = 0,
          kernel_factory: Callable[..., Kernel] = Kernel) -> list[Violation]:
    """Concurrent twin of `fuzz`. Drives `ainvoke`/`aspawn` in batches.

    `kernel_factory` exists for negative controls: tests plant a deliberately
    racy kernel and assert this fuzzer catches it.
    """
    return asyncio.run(_afuzz(policy, rounds=rounds, batch=batch, seed=seed,
                              kernel_factory=kernel_factory))


async def _afuzz(policy: Policy, *, rounds: int, batch: int, seed: int,
                 kernel_factory: Callable[..., Kernel]) -> list[Violation]:
    rng = random.Random(seed)
    registry, recorder = build_fixture_registry(
        policy, async_rng=random.Random(seed ^ 0x5EED))
    kernel = kernel_factory(registry)
    root = Grant.root(policy, "root")
    live: list[Grant] = [root]
    violations: list[Violation] = []
    tools = sorted(policy.tool_names | _OFF_POLICY)

    async def op(i: int) -> None:
        grant = _pick_grant(rng, live)
        roll = rng.random()
        try:
            if roll < 0.2:
                req = SpawnRequest(
                    name=f"a{i}",
                    tools=frozenset(rng.sample(tools, rng.randint(0, min(3, len(tools))))),
                    budget_fraction=rng.choice([0.1, 0.5, 0.9, 1.0, 2.0]))
                live.append(await kernel.aspawn(grant, req))
            elif roll < 0.25 and len(live) > 1:
                kernel.revoke(rng.choice(live[1:]))
            else:
                tool, args = _pick_call(rng, tools)
                await kernel.ainvoke(grant, tool, **args)
        except PolicyViolation:
            pass                      # denial is a valid outcome
        except Exception as exc:      # anything else is a framework bug
            violations.append(Violation("kernel_crash",
                                        f"{type(exc).__name__}: {exc}"))

    def snapshot() -> tuple[int, int, int]:
        return (len(kernel.audit), len(recorder.calls), root.ledger.tool_calls)

    async def watcher(stop: asyncio.Event) -> None:
        # Yield at every scheduling point while the batch is in flight, but
        # only re-check when observable state moved. Checking on every spin
        # made each spin O(audit length) and starved the worker threads of
        # the GIL -- the run went quadratic on slow CI runners.
        last = None
        while not stop.is_set():
            now = snapshot()
            if now != last:
                violations.extend(_check_all(root, kernel, recorder))
                last = now
            await asyncio.sleep(0)

    for r in range(rounds):
        stop = asyncio.Event()
        watch = asyncio.create_task(watcher(stop))
        tasks = [asyncio.create_task(op(r * batch + j)) for j in range(batch)]
        await asyncio.sleep(0)
        for t in tasks:
            if rng.random() < 0.1:
                t.cancel()            # a cancelled call must still have been paid for
        await asyncio.gather(*tasks, return_exceptions=True)
        stop.set()
        await watch
        violations.extend(_check_all(root, kernel, recorder))
        if violations:
            break
    return violations

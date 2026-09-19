"""The kernel: the one place an effect can happen.

Design rule -- exactly two functions in this codebase call a registered tool
implementation: `Kernel._execute` (sync) and `Kernel._aexecute` (async). Both
are reached only through `invoke` / `ainvoke`, which share one admission path
(`_admit`) and one post-guard path (`_release`), so the sync and async entry
points cannot drift apart. If you add a third call site, the guarantee is gone;
`test_kernel_is_the_only_execution_path` asserts this statically.

Ordering of the chain matters:
  1. pre-guards  -- may deny. Any exception is caught and converted to DENY.
  2. budget charge -- reserved *before* execution so a crash still costs.
  3. execute
  4. post-guards -- may deny on the *result* (classification, taint), in which
     case the result is discarded and never returned to the agent.
"""
from __future__ import annotations

import asyncio
import inspect
import threading
from dataclasses import dataclass
from typing import Any, Sequence

from .audit import AuditLog
from .decision import BudgetExhausted, PolicyViolation, Verdict
from .grant import Grant, SpawnRequest
from .guards import DEFAULT_GUARDS, DEFAULT_POST_GUARDS, Call
from .policy import Policy, PolicyError
from .registry import ToolRegistry

SPAWN_TOOL = "agent.spawn"
SPEND_TOOL = "model.spend"


@dataclass(frozen=True)
class SpendReservation:
    """Budget held for a model call between `reserve_spend` and `settle_spend`."""
    grant: Grant
    usd: float
    tokens: int
    label: str


class Kernel:
    def __init__(self, registry: ToolRegistry, *,
                 guards: Sequence[Any] = DEFAULT_GUARDS,
                 post_guards: Sequence[Any] = DEFAULT_POST_GUARDS,
                 audit: AuditLog | None = None,
                 dry_run: bool = False):
        self.registry = registry
        self.guards = tuple(guards)
        self.post_guards = tuple(post_guards)
        # `audit or AuditLog()` would discard a caller's empty log: AuditLog has __len__, so a
        # fresh file-backed log is falsy and its records silently went to a throwaway instance.
        self.audit = audit if audit is not None else AuditLog()
        self.dry_run = dry_run          # conformance mode: never execute
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Decision only -- no side effect. Used by conformance and by callers
    # that want to pre-check.
    # ------------------------------------------------------------------
    def decide(self, grant: Grant, call: Call) -> Verdict:
        for guard in self.guards:
            try:
                verdict = guard.check(grant, call)
            except Exception as exc:                      # fail closed
                verdict = Verdict.deny(
                    "guard.internal_error",
                    f"guard '{getattr(guard, 'name', guard)}' raised: {exc!r}",
                    getattr(guard, "name", "unknown"))
            if not verdict.allowed:
                return verdict
        return Verdict.allow("kernel.admitted", "kernel")

    # ------------------------------------------------------------------
    def invoke(self, grant: Grant, tool: str, /, **args) -> Any:
        spec, call = self._admit(grant, tool, args, is_async=False)
        if self.dry_run:
            return None
        result = self._execute(spec, call)
        if inspect.isawaitable(result):
            # A sync-registered tool that hands back a coroutine. Nothing has
            # run yet; refuse rather than return an unmediated awaitable.
            if inspect.iscoroutine(result):
                result.close()
            self._deny_async(grant, call)
        return self._release(grant, call, result)

    async def ainvoke(self, grant: Grant, tool: str, /, **args) -> Any:
        """Async twin of `invoke`. Same guards, same ledger, same audit.

        Coroutine tools are awaited on the running loop; plain tools run in a
        worker thread so a blocking implementation cannot stall the loop.
        """
        spec, call = self._admit(grant, tool, args, is_async=True)
        if self.dry_run:
            return None
        result = await self._aexecute(spec, call)
        return self._release(grant, call, result)

    # ------------------------------------------------------------------
    def _admit(self, grant: Grant, tool: str, args: dict, *, is_async: bool):
        """Everything before execution. Raises PolicyViolation or returns
        (spec, call) with the budget already charged."""
        call = Call(tool=tool, args=dict(args))
        spec = self.registry.spec(tool)
        if spec is not None:
            call.est_usd = spec.cost_usd
            call.meta["classification"] = spec.classification

        # Spawning is not a tool call: it mints authority, so it has its own
        # entry point with its own guard path. Found by the fuzzer.
        if tool == SPAWN_TOOL:
            verdict = Verdict.deny(
                "kernel.spawn_requires_api",
                "agent.spawn cannot be invoked as a tool; use Kernel.spawn()",
                "kernel")
            self._log(grant, call, verdict)
            raise PolicyViolation(verdict, tool, grant.agent_name)

        verdict = self.decide(grant, call)

        # An allowlisted-but-unregistered tool is a config error: deny.
        if verdict.allowed and spec is None:
            verdict = Verdict.deny(
                "registry.unknown_tool",
                f"'{tool}' is policy-allowed but not registered", "kernel")

        # A coroutine tool invoked synchronously would return an unawaited
        # coroutine: the effect would escape the post-guards. Refuse up front,
        # before any budget is charged.
        if verdict.allowed and spec.is_async and not is_async:
            verdict = Verdict.deny(
                "kernel.async_tool_requires_ainvoke",
                f"'{tool}' is a coroutine tool; call it with ainvoke()", "kernel")

        self._log(grant, call, verdict)
        if not verdict.allowed:
            raise PolicyViolation(verdict, tool, grant.agent_name)

        charged = grant.ledger.charge(usd=call.est_usd, tokens=call.est_tokens, calls=1)
        if not charged.allowed:
            self._log(grant, call, charged)
            raise PolicyViolation(charged, tool, grant.agent_name)
        return spec, call

    def _release(self, grant: Grant, call: Call, result: Any) -> Any:
        """Post-guards. A denial here discards the result."""
        for pg in self.post_guards:
            try:
                pv = pg.inspect(grant, call, result)
            except Exception as exc:
                pv = Verdict.deny("guard.internal_error",
                                  f"post-guard raised: {exc!r}",
                                  getattr(pg, "name", "unknown"))
            if not pv.allowed:
                self._log(grant, call, pv)
                raise PolicyViolation(pv, call.tool, grant.agent_name)
        return result

    def _deny_async(self, grant: Grant, call: Call) -> None:
        verdict = Verdict.deny(
            "kernel.async_tool_requires_ainvoke",
            f"'{call.tool}' returned an awaitable; call it with ainvoke()", "kernel")
        self._log(grant, call, verdict)
        raise PolicyViolation(verdict, call.tool, grant.agent_name)

    # -- THE ONLY TWO CALL SITES --------------------------------------
    def _execute(self, spec, call: Call) -> Any:
        return spec.fn(**call.args)

    async def _aexecute(self, spec, call: Call) -> Any:
        if spec.is_async:
            return await spec.fn(**call.args)
        result = await asyncio.to_thread(self._execute, spec, call)
        if inspect.isawaitable(result):
            result = await result
        return result

    # ------------------------------------------------------------------
    def spawn(self, parent: Grant, req: SpawnRequest) -> Grant:
        """Create a child grant. Structural limits first, then attenuation."""
        call = Call(tool=SPAWN_TOOL,
                    args={"name": req.name, "tools": sorted(req.tools)})
        verdict = self.decide(parent, call)
        if verdict.allowed:
            try:
                child = parent.attenuate(req)
            except PolicyError as exc:
                rule = str(exc).split(":", 1)[0]
                verdict = Verdict.deny(rule, str(exc), "spawn")
        self._log(parent, call, verdict)
        if not verdict.allowed:
            raise PolicyViolation(verdict, SPAWN_TOOL, parent.agent_name)
        parent.ledger.charge(calls=1)
        return child

    async def aspawn(self, parent: Grant, req: SpawnRequest) -> Grant:
        """Spawning does no I/O; this exists so async callers never have to
        reach for the sync API mid-coroutine."""
        return self.spawn(parent, req)

    # ------------------------------------------------------------------
    # Model spend. A model call is not a tool call -- it has no implementation
    # in the registry and nothing is executed here -- but it spends the same
    # budget. Callers reserve an estimate before the request and settle the
    # actual cost after it, so the ledger is a hard gate rather than a report.
    # ------------------------------------------------------------------
    def reserve_spend(self, grant: Grant, *, usd: float = 0.0, tokens: int = 0,
                      label: str = "model") -> SpendReservation:
        """Hold `usd`/`tokens` against the grant's ledger and every ancestor's.

        Raises BudgetExhausted if the estimate does not fit, or PolicyViolation
        (`grant.revoked`) if the grant or an ancestor has been revoked. A zero
        estimate is a pure pre-flight check: it still denies an exhausted
        budget or a passed deadline.
        """
        call = Call(tool=SPEND_TOOL, args={"label": label, "usd": usd, "tokens": tokens})
        if not grant.is_active():
            verdict = Verdict.deny("grant.revoked", f"grant {grant.grant_id} is revoked",
                                   "capability")
        else:
            verdict = grant.ledger.charge(usd=usd, tokens=tokens, calls=0)
            if verdict.allowed:
                verdict = Verdict.allow("budget.reserved", "budget", usd=usd, tokens=tokens)
        self._log(grant, call, verdict)
        if not verdict.allowed:
            exc = BudgetExhausted if verdict.rule.startswith("budget.") else PolicyViolation
            raise exc(verdict, SPEND_TOOL, grant.agent_name)
        return SpendReservation(grant, usd, tokens, label)

    def settle_spend(self, reservation: SpendReservation, *, usd: float,
                     tokens: int = 0) -> None:
        """Replace the reservation with the actual cost. Always recorded, even
        when it overruns: the spend already happened, and the overrun is what
        makes the next reservation fail."""
        g = reservation.grant
        with self._lock:
            g.ledger.refund(usd=reservation.usd, tokens=reservation.tokens, calls=0)
            g.ledger.record(usd=usd, tokens=tokens)
        self._log(g, Call(tool=SPEND_TOOL,
                          args={"label": reservation.label, "usd": usd, "tokens": tokens}),
                  Verdict.allow("budget.settled", "budget", usd=usd, tokens=tokens,
                                reserved_usd=reservation.usd))

    # ------------------------------------------------------------------
    def revoke(self, grant: Grant, reason: str = "operator") -> None:
        grant.revoke()
        self._log(grant, Call(tool="agent.revoke", args={"reason": reason}),
                  Verdict.allow("grant.revoked_subtree", "kernel"))

    def _log(self, grant: Grant, call: Call, verdict: Verdict) -> None:
        self.audit.append(agent=grant.agent_name, grant_id=grant.grant_id,
                          depth=grant.depth, tool=call.tool, args=call.args,
                          verdict=verdict)


def build_kernel(policy: Policy, registry: ToolRegistry, *,
                 constitution=None, ratify: bool = True, **kw) -> tuple[Kernel, Grant]:
    """Supported entry point: ratify the policy, then build kernel + root grant.

    Ratification is on by default and has no waiver flag in the policy itself.
    `ratify=False` exists only so tests can construct deliberately invalid
    policies; production code should never pass it.
    """
    if ratify:
        from .constitution import default_constitution
        (constitution or default_constitution()).ratify(policy, registry)
    kernel = Kernel(registry, **kw)
    return kernel, Grant.root(policy)

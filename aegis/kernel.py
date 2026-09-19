"""The kernel: the one place an effect can happen.

Design rule -- there is exactly one function in this codebase that calls a
registered tool implementation (`Kernel._execute`). Everything else must route
through `Kernel.invoke`, which runs the guard chain first. If you add a second
call site, the guarantee is gone; `tests/test_kernel_is_sole_callsite.py`
asserts this statically.

Ordering of the chain matters:
  1. pre-guards  -- may deny. Any exception is caught and converted to DENY.
  2. budget charge -- reserved *before* execution so a crash still costs.
  3. execute
  4. post-guards -- may deny on the *result* (classification, taint), in which
     case the result is discarded and never returned to the agent.
"""
from __future__ import annotations

import threading
from typing import Any, Iterable, Sequence

from .audit import AuditLog
from .decision import PolicyViolation, Verdict
from .grant import Grant, SpawnRequest
from .guards import DEFAULT_GUARDS, DEFAULT_POST_GUARDS, Call
from .policy import Policy, PolicyError
from .registry import ToolRegistry

SPAWN_TOOL = "agent.spawn"


class Kernel:
    def __init__(self, registry: ToolRegistry, *,
                 guards: Sequence[Any] = DEFAULT_GUARDS,
                 post_guards: Sequence[Any] = DEFAULT_POST_GUARDS,
                 audit: AuditLog | None = None,
                 dry_run: bool = False):
        self.registry = registry
        self.guards = tuple(guards)
        self.post_guards = tuple(post_guards)
        self.audit = audit or AuditLog()
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

        self._log(grant, call, verdict)
        if not verdict.allowed:
            raise PolicyViolation(verdict, tool, grant.agent_name)

        charged = grant.ledger.charge(usd=call.est_usd, tokens=call.est_tokens, calls=1)
        if not charged.allowed:
            self._log(grant, call, charged)
            raise PolicyViolation(charged, tool, grant.agent_name)

        if self.dry_run:
            return None

        result = self._execute(spec, call)

        for pg in self.post_guards:
            try:
                pv = pg.inspect(grant, call, result)
            except Exception as exc:
                pv = Verdict.deny("guard.internal_error",
                                  f"post-guard raised: {exc!r}",
                                  getattr(pg, "name", "unknown"))
            if not pv.allowed:
                self._log(grant, call, pv)
                raise PolicyViolation(pv, tool, grant.agent_name)

        return result

    # -- THE ONLY CALL SITE -------------------------------------------
    def _execute(self, spec, call: Call) -> Any:
        return spec.fn(**call.args)

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

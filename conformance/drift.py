"""Privilege drift detection.

The regression risk with a policy-as-data system is not that the enforcement
breaks -- the conformance suite catches that. It is that someone quietly
*loosens the policy* and every test still passes, because the tests now agree
with the weaker rules.

So the suite diffs the proposed policy against the pinned baseline and fails
on any widening unless it is explicitly acknowledged with a waiver.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aegis.policy import ArgConstraint, Policy, load_policy


@dataclass(frozen=True)
class Delta:
    kind: str            # "widened" | "narrowed"
    code: str            # stable id, e.g. "tools.added"
    detail: str

    def __str__(self) -> str:
        arrow = "+" if self.kind == "widened" else "-"
        return f"{arrow} [{self.code}] {self.detail}"


def _constraint_widened(old: ArgConstraint | None,
                        new: ArgConstraint | None) -> list[str]:
    """Conservative: treat any relaxation or any change we cannot prove is a
    tightening as widening."""
    out: list[str] = []
    if old is None:
        return out if new is None else []
    if new is None:
        return ["constraint removed entirely"]

    if old.prefix and (not new.prefix or not new.prefix.startswith(old.prefix)):
        out.append(f"prefix '{old.prefix}' -> '{new.prefix}'")
    if old.matches and new.matches != old.matches:
        out.append(f"regex changed '{old.matches}' -> '{new.matches}'")
    if old.forbid_matches and not new.forbid_matches:
        out.append(f"forbid_matches '{old.forbid_matches}' removed")
    if old.one_of is not None and (new.one_of is None
                                   or not set(new.one_of) <= set(old.one_of)):
        out.append(f"one_of widened {old.one_of} -> {new.one_of}")
    if old.max_len is not None and (new.max_len is None or new.max_len > old.max_len):
        out.append(f"max_len {old.max_len} -> {new.max_len}")
    if old.max_value is not None and (new.max_value is None
                                      or new.max_value > old.max_value):
        out.append(f"max_value {old.max_value} -> {new.max_value}")
    return out


def diff_policies(old: Policy, new: Policy) -> list[Delta]:
    out: list[Delta] = []

    # -- tools ----------------------------------------------------------
    added = new.tool_names - old.tool_names
    removed = old.tool_names - new.tool_names
    for t in sorted(added):
        out.append(Delta("widened", "tools.added", f"new tool granted: {t}"))
    for t in sorted(removed):
        out.append(Delta("narrowed", "tools.removed", f"tool revoked: {t}"))

    for t in sorted(old.tool_names & new.tool_names):
        o, n = old.tools[t], new.tools[t]
        dropped_req = set(o.require_args) - set(n.require_args)
        if dropped_req:
            out.append(Delta("widened", "tools.require_args_dropped",
                             f"{t}: no longer requires {sorted(dropped_req)}"))
        if o.deny_extra_args and not n.deny_extra_args:
            out.append(Delta("widened", "tools.extra_args_allowed",
                             f"{t}: now accepts unlisted arguments"))
        for arg in sorted(set(o.args) | set(n.args)):
            for why in _constraint_widened(o.args.get(arg), n.args.get(arg)):
                out.append(Delta("widened", "tools.constraint_relaxed",
                                 f"{t}.{arg}: {why}"))

    # -- effects --------------------------------------------------------
    for e in sorted(new.effects - old.effects):
        out.append(Delta("widened", "effects.added", f"effect class {e.value}"))

    # -- budget ---------------------------------------------------------
    for field_ in ("usd", "tokens", "wall_clock_s", "tool_calls"):
        ov, nv = getattr(old.budget, field_), getattr(new.budget, field_)
        if nv > ov:
            out.append(Delta("widened", f"budget.{field_}_raised",
                             f"{field_} {ov} -> {nv}"))
        elif nv < ov:
            out.append(Delta("narrowed", f"budget.{field_}_lowered",
                             f"{field_} {ov} -> {nv}"))

    # -- data -----------------------------------------------------------
    if int(new.data.max_classification) > int(old.data.max_classification):
        out.append(Delta("widened", "data.read_ceiling_raised",
                         f"{old.data.max_classification.name} -> "
                         f"{new.data.max_classification.name}"))
    if int(new.data.egress_max_classification) > int(old.data.egress_max_classification):
        out.append(Delta("widened", "data.egress_ceiling_raised",
                         f"{old.data.egress_max_classification.name} -> "
                         f"{new.data.egress_max_classification.name}"))
    for k in sorted(old.data.block_pii - new.data.block_pii):
        out.append(Delta("widened", "data.pii_check_removed",
                         f"no longer blocks {k} on egress"))
    for s in sorted(old.data.egress_sinks - new.data.egress_sinks):
        out.append(Delta("widened", "data.egress_sink_unmonitored",
                         f"{s} no longer treated as an egress sink"))
    if new.data.redact_instead_of_deny and not old.data.redact_instead_of_deny:
        out.append(Delta("widened", "data.deny_downgraded_to_redact",
                         "PII egress now redacted rather than refused"))

    # -- spawn ----------------------------------------------------------
    for field_ in ("max_depth", "max_fanout", "max_descendants",
                   "child_budget_fraction"):
        ov, nv = getattr(old.spawn, field_), getattr(new.spawn, field_)
        if nv > ov:
            out.append(Delta("widened", f"spawn.{field_}_raised",
                             f"{field_} {ov} -> {nv}"))
    oa, na = old.spawn.allow_tools, new.spawn.allow_tools
    if oa is not None:
        if na is None:
            out.append(Delta("widened", "spawn.delegable_unbounded",
                             "children may now inherit any parent tool"))
        else:
            for t in sorted(na - oa):
                out.append(Delta("widened", "spawn.delegable_added",
                                 f"{t} is now delegable to children"))
    return out


def widenings(old: Policy, new: Policy) -> list[Delta]:
    return [d for d in diff_policies(old, new) if d.kind == "widened"]


def check_drift(baseline: str | Path, candidate: str | Path,
                waivers: set[str] | None = None) -> tuple[bool, list[Delta]]:
    """Return (ok, deltas). ok is False if any unwaived widening is present."""
    w = waivers or set()
    deltas = diff_policies(load_policy(baseline), load_policy(candidate))
    offending = [d for d in deltas
                 if d.kind == "widened" and d.code not in w]
    return (not offending), deltas

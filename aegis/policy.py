"""Declarative policy: the single source of truth for what an agent may do.

Policies are data, not code. That matters for three reasons:
  1. They can be diffed (see aegis/conformance/drift.py) to detect privilege widening.
  2. They can be signed/pinned and shipped independently of agent code.
  3. An agent cannot author or mutate one at runtime.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from .decision import Classification, Effect

# --------------------------------------------------------------------------
# Argument constraints
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ArgConstraint:
    """Constraint on a single tool argument. All present checks must pass."""
    matches: str | None = None        # full-match regex
    prefix: str | None = None
    one_of: tuple[Any, ...] | None = None
    max_len: int | None = None
    max_value: float | None = None
    forbid_matches: str | None = None  # deny if regex found anywhere

    def check(self, value: Any) -> str | None:
        """Return a rule-id suffix on failure, None on pass."""
        s = value if isinstance(value, str) else str(value)
        if self.matches is not None and not re.fullmatch(self.matches, s):
            return "regex"
        if self.prefix is not None and not s.startswith(self.prefix):
            return "prefix"
        if self.one_of is not None and value not in self.one_of:
            return "enum"
        if self.max_len is not None and len(s) > self.max_len:
            return "max_len"
        if self.max_value is not None:
            try:
                if float(value) > self.max_value:
                    return "max_value"
            except (TypeError, ValueError):
                return "max_value"
        if self.forbid_matches is not None and re.search(self.forbid_matches, s):
            return "forbidden_pattern"
        return None

    def intersect(self, other: "ArgConstraint") -> "ArgConstraint":
        """Strictest-wins merge. Used when attenuating a grant."""
        def pick(a, b, tighter):
            if a is None:
                return b
            if b is None:
                return a
            return tighter(a, b)

        return ArgConstraint(
            matches=pick(self.matches, other.matches, lambda a, b: a if a == b else f"(?={a}){b}"),
            prefix=pick(self.prefix, other.prefix, lambda a, b: a if a.startswith(b) else b),
            one_of=pick(self.one_of, other.one_of,
                        lambda a, b: tuple(x for x in a if x in b)),
            max_len=pick(self.max_len, other.max_len, min),
            max_value=pick(self.max_value, other.max_value, min),
            forbid_matches=pick(self.forbid_matches, other.forbid_matches,
                                lambda a, b: a if a == b else f"({a})|({b})"),
        )

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ArgConstraint":
        known = {f for f in ArgConstraint.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise PolicyError(f"unknown arg constraint keys: {sorted(unknown)}")
        one_of = d.get("one_of")
        return ArgConstraint(
            matches=d.get("matches"),
            prefix=d.get("prefix"),
            one_of=tuple(one_of) if one_of is not None else None,
            max_len=d.get("max_len"),
            max_value=d.get("max_value"),
            forbid_matches=d.get("forbid_matches"),
        )


@dataclass(frozen=True)
class ToolRule:
    name: str
    args: dict[str, ArgConstraint] = field(default_factory=dict)
    require_args: tuple[str, ...] = ()      # these args must be present
    deny_extra_args: bool = True            # unknown args are refused

    def intersect(self, other: "ToolRule") -> "ToolRule":
        args = dict(self.args)
        for k, c in other.args.items():
            args[k] = args[k].intersect(c) if k in args else c
        return ToolRule(
            name=self.name,
            args=args,
            require_args=tuple(sorted(set(self.require_args) | set(other.require_args))),
            deny_extra_args=self.deny_extra_args or other.deny_extra_args,
        )


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Budget:
    usd: float = 0.0
    tokens: int = 0
    wall_clock_s: float = 0.0
    tool_calls: int = 0

    def scaled(self, f: float) -> "Budget":
        return Budget(self.usd * f, int(self.tokens * f),
                      self.wall_clock_s * f, int(self.tool_calls * f))

    def le(self, other: "Budget") -> bool:
        return (self.usd <= other.usd and self.tokens <= other.tokens
                and self.wall_clock_s <= other.wall_clock_s
                and self.tool_calls <= other.tool_calls)


@dataclass(frozen=True)
class DataPolicy:
    max_classification: Classification = Classification.INTERNAL
    egress_sinks: frozenset[str] = frozenset()
    egress_max_classification: Classification = Classification.PUBLIC
    block_pii: frozenset[str] = frozenset()
    redact_instead_of_deny: bool = False


@dataclass(frozen=True)
class SpawnPolicy:
    max_depth: int = 0
    max_fanout: int = 0
    max_descendants: int = 0
    child_budget_fraction: float = 0.5
    allow_tools: frozenset[str] | None = None  # None => children may inherit any parent tool


@dataclass(frozen=True)
class Policy:
    name: str
    version: int = 1
    tools: dict[str, ToolRule] = field(default_factory=dict)
    effects: frozenset[Effect] = frozenset()
    budget: Budget = Budget()
    data: DataPolicy = DataPolicy()
    spawn: SpawnPolicy = SpawnPolicy()

    # ---- derived -------------------------------------------------------
    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(self.tools)

    def rule_for(self, tool: str) -> ToolRule | None:
        return self.tools.get(tool)

    def restricted_to(self, tools: set[str]) -> "Policy":
        """Return a copy holding only `tools` (must be a subset)."""
        extra = tools - self.tool_names
        if extra:
            raise PolicyError(f"cannot widen: {sorted(extra)} not in parent policy")
        return replace(self, tools={k: v for k, v in self.tools.items() if k in tools})


class PolicyError(ValueError):
    pass


# --------------------------------------------------------------------------
# Loader
# --------------------------------------------------------------------------

_TOP_LEVEL = {"name", "version", "tools", "effects", "budget", "data", "spawn", "extends"}


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path}: not valid YAML: {exc}") from exc
    if raw is None:
        raw = {}                        # an empty file is an empty (unratifiable) policy
    if not isinstance(raw, dict):
        raise PolicyError(f"{path}: a policy must be a mapping, got {type(raw).__name__}")
    base = None
    if "extends" in raw:
        base = load_policy(path.parent / raw["extends"])
    return parse_policy(raw, base=base, source=str(path))


def parse_policy(raw: dict[str, Any], base: Policy | None = None,
                 source: str = "<policy>") -> Policy:
    """Parse a policy mapping. Any structural problem -- a list where a
    mapping belongs, a string where a number does -- is a PolicyError naming
    the source, never a TypeError from deep inside the parser. Callers (and
    CI exit codes) depend on telling "bad input" apart from "framework bug"."""
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: a policy must be a mapping, got {type(raw).__name__}")
    try:
        return _parse_policy(raw, base=base, source=source)
    except PolicyError:
        raise
    except (TypeError, AttributeError, ValueError, KeyError) as exc:
        raise PolicyError(f"{source}: malformed policy: {exc}") from exc


def _parse_policy(raw: dict[str, Any], base: Policy | None = None,
                 source: str = "<dict>") -> Policy:
    unknown = set(raw) - _TOP_LEVEL
    if unknown:
        raise PolicyError(f"{source}: unknown top-level keys {sorted(unknown)}")

    # Tools -------------------------------------------------------------
    tools: dict[str, ToolRule] = dict(base.tools) if base else {}
    tsec = raw.get("tools") or {}
    if "deny" in tsec:
        for name in tsec["deny"]:
            tools.pop(name, None)
    for entry in tsec.get("allow", []):
        if isinstance(entry, str):
            entry = {"name": entry}
        name = entry["name"]
        args = {k: ArgConstraint.from_dict(v)
                for k, v in (entry.get("args") or {}).items()}
        rule = ToolRule(
            name=name,
            args=args,
            require_args=tuple(entry.get("require_args", ())),
            deny_extra_args=entry.get("deny_extra_args", True),
        )
        # An `extends` child may only tighten an inherited rule.
        tools[name] = tools[name].intersect(rule) if name in tools else rule

    # Effects -----------------------------------------------------------
    eff = raw.get("effects")
    effects = (frozenset(Effect(e) for e in eff) if eff is not None
               else (base.effects if base else frozenset(Effect)))

    # Budget ------------------------------------------------------------
    bsec = raw.get("budget") or {}
    bbase = base.budget if base else Budget()
    budget = Budget(
        usd=float(bsec.get("usd", bbase.usd)),
        tokens=int(bsec.get("tokens", bbase.tokens)),
        wall_clock_s=float(bsec.get("wall_clock_s", bbase.wall_clock_s)),
        tool_calls=int(bsec.get("tool_calls", bbase.tool_calls)),
    )
    if base and not budget.le(bbase):
        raise PolicyError(f"{source}: child policy raises budget above parent")

    # Data --------------------------------------------------------------
    dsec = raw.get("data") or {}
    dbase = base.data if base else DataPolicy()
    egress = dsec.get("egress") or {}
    data = DataPolicy(
        max_classification=Classification.parse(
            dsec.get("max_classification", dbase.max_classification)),
        egress_sinks=frozenset(egress.get("sinks", dbase.egress_sinks)),
        egress_max_classification=Classification.parse(
            egress.get("max_classification", dbase.egress_max_classification)),
        block_pii=frozenset(egress.get("block_pii", dbase.block_pii)),
        redact_instead_of_deny=bool(
            egress.get("redact_instead_of_deny", dbase.redact_instead_of_deny)),
    )

    # Spawn -------------------------------------------------------------
    ssec = raw.get("spawn") or {}
    sbase = base.spawn if base else SpawnPolicy()
    at = ssec.get("allow_tools", None)
    spawn = SpawnPolicy(
        max_depth=int(ssec.get("max_depth", sbase.max_depth)),
        max_fanout=int(ssec.get("max_fanout", sbase.max_fanout)),
        max_descendants=int(ssec.get("max_descendants", sbase.max_descendants)),
        child_budget_fraction=float(
            ssec.get("child_budget_fraction", sbase.child_budget_fraction)),
        allow_tools=frozenset(at) if at is not None else sbase.allow_tools,
    )
    if not 0.0 < spawn.child_budget_fraction <= 1.0:
        raise PolicyError(f"{source}: child_budget_fraction must be in (0, 1]")

    return Policy(
        name=raw.get("name", base.name if base else "unnamed"),
        version=int(raw.get("version", 1)),
        tools=tools, effects=effects, budget=budget, data=data, spawn=spawn,
    )


# --------------------------------------------------------------------------
# Serialisation
# --------------------------------------------------------------------------

_ARG_KEYS = ("matches", "prefix", "one_of", "max_len", "max_value", "forbid_matches")


def dump_policy(policy: Policy) -> dict[str, Any]:
    """Policy -> plain mapping that `parse_policy` turns back into an equal Policy.

    Used to write generated policies to YAML and to fingerprint the policy a
    run was governed by (`policy_digest`).
    """
    tools = []
    for name in sorted(policy.tools):
        rule = policy.tools[name]
        entry: dict[str, Any] = {"name": name}
        if rule.require_args:
            entry["require_args"] = list(rule.require_args)
        if not rule.deny_extra_args:
            entry["deny_extra_args"] = False
        args = {}
        for arg in sorted(rule.args):
            c = rule.args[arg]
            d = {k: getattr(c, k) for k in _ARG_KEYS if getattr(c, k) is not None}
            if "one_of" in d:
                d["one_of"] = list(d["one_of"])
            args[arg] = d
        if args:
            entry["args"] = args
        tools.append(entry)
    b, dp, sp = policy.budget, policy.data, policy.spawn
    spawn: dict[str, Any] = {"max_depth": sp.max_depth, "max_fanout": sp.max_fanout,
                             "max_descendants": sp.max_descendants,
                             "child_budget_fraction": sp.child_budget_fraction}
    if sp.allow_tools is not None:
        spawn["allow_tools"] = sorted(sp.allow_tools)
    return {
        "name": policy.name,
        "version": policy.version,
        "effects": sorted(e.value for e in policy.effects),
        "tools": {"allow": tools},
        "budget": {"usd": b.usd, "tokens": b.tokens, "wall_clock_s": b.wall_clock_s,
                   "tool_calls": b.tool_calls},
        "data": {
            "max_classification": dp.max_classification.name.lower(),
            "egress": {"sinks": sorted(dp.egress_sinks),
                       "max_classification": dp.egress_max_classification.name.lower(),
                       "block_pii": sorted(dp.block_pii),
                       "redact_instead_of_deny": dp.redact_instead_of_deny},
        },
        "spawn": spawn,
    }


def policy_digest(policy: Policy) -> str:
    """Stable content fingerprint: equal policies have equal digests."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps(dump_policy(policy), sort_keys=True).encode()).hexdigest()[:16]

"""Loophole detection.

The conformance suite answers "do the rules I wrote still work?". This module
answers the harder question: "what gets through that I never thought to test?"

Three techniques, in increasing order of how much they surprise you:

  1. STATIC   -- structural analysis of the policy and registry together.
                 Finds rules that cannot fire, exits nobody screens, and
                 delegation shapes that recombine authority.
  2. PROBE    -- push a corpus of known-dangerous payloads through the real
                 guard chain in decision-only mode. Anything ALLOWED is a
                 loophole with a concrete witness string.
  3. METAMORPHIC -- take every step the suite expects to be DENIED, mutate the
                 arguments in ways that preserve the dangerous meaning
                 (encoding, case, whitespace, comments), and re-run. A
                 mutation that flips DENY to ALLOW is a bypass.

Findings carry a stable fingerprint. Accepted ones live in
`loopholes.baseline.yaml` with a written reason; anything new fails CI. That
is the regression property: the set of known holes may shrink silently but can
never grow silently.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

from aegis.decision import Classification, Effect
from aegis.grant import Grant
from aegis.guards import Call
from aegis.kernel import Kernel
from aegis.policy import ArgConstraint, Policy, ToolRule
from aegis.registry import ToolRegistry

from .fixtures import build_fixture_registry
from .spec import Step, load_suite

SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    tool: str = ""
    arg: str = ""
    witness: str = ""

    @property
    def fingerprint(self) -> str:
        key = f"{self.category}|{self.tool}|{self.arg}|{self.title}|{self.witness}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def __str__(self) -> str:
        loc = f" {self.tool}" + (f".{self.arg}" if self.arg else "") if self.tool else ""
        w = f"\n        witness: {self.witness!r}" if self.witness else ""
        return (f"[{self.severity.upper():8}] {self.fingerprint}  "
                f"{self.category}{loc}\n        {self.detail}{w}")


# ======================================================================
# 1. STATIC ANALYSIS
# ======================================================================

_SUSPECT_REGEX = [
    (r"(?<!\\)\.\*", "contains an unescaped .* wildcard"),
    (r"(?<!\\)\.\+", "contains an unescaped .+ wildcard"),
    (r"\(\?s\)|\(\?[a-z]*s[a-z]*\)", "DOTALL is on, so . matches newlines"),
    (r"\[\^", "uses a negated character class, which admits more than it looks"),
]


def static_findings(policy: Policy, registry: ToolRegistry) -> list[Finding]:
    out: list[Finding] = []

    # -- unscreened exits ------------------------------------------------
    for name in sorted(policy.tool_names):
        spec = registry.spec(name)
        if spec is None:
            continue
        outward = spec.effects & {Effect.EGRESS, Effect.NETWORK, Effect.WRITE}
        if outward and name not in policy.data.egress_sinks:
            out.append(Finding(
                "unscreened_exit", "high", "data can leave unscreened",
                f"declares {sorted(e.value for e in outward)} but is not a "
                f"declared egress sink, so PII and taint checks never run",
                tool=name))

    # -- rules that cannot fire -----------------------------------------
    from aegis.guards.data import _PATTERNS
    known_pii = set(_PATTERNS) | {"credit_card"}
    for kind in sorted(policy.data.block_pii - known_pii):
        out.append(Finding(
            "dead_rule", "high", "PII rule has no detector",
            f"'{kind}' is listed in block_pii but nothing detects it; the rule "
            f"reads as protection and never fires", arg=kind))

    for name in sorted(policy.tool_names):
        if registry.spec(name) is None and name != "agent.spawn":
            out.append(Finding(
                "phantom_grant", "medium", "grant with no implementation",
                "granted by policy but not registered; the grant activates "
                "silently the day someone registers this name", tool=name))

    # -- unconstrained surface ------------------------------------------
    for name, rule in sorted(policy.tools.items()):
        spec = registry.spec(name)
        effectful = bool(spec and spec.effects &
                         {Effect.WRITE, Effect.NETWORK, Effect.EGRESS})
        for arg in rule.require_args:
            if arg not in rule.args:
                out.append(Finding(
                    "unconstrained_arg", "high" if effectful else "medium",
                    "argument accepts any value",
                    "required by the policy but carries no constraint",
                    tool=name, arg=arg))
        for arg, c in sorted(rule.args.items()):
            if _is_empty(c):
                out.append(Finding(
                    "unconstrained_arg", "medium", "empty constraint",
                    "constraint object is present but imposes nothing",
                    tool=name, arg=arg))
            if c.matches:
                for pat, why in _SUSPECT_REGEX:
                    if re.search(pat, c.matches):
                        out.append(Finding(
                            "weak_regex", "medium", "permissive pattern",
                            f"{why}: {c.matches}", tool=name, arg=arg))
                if not c.matches.startswith("^") and not c.matches.startswith("(?"):
                    out.append(Finding(
                        "weak_regex", "medium", "unanchored pattern",
                        f"pattern is not anchored at the start: {c.matches}",
                        tool=name, arg=arg))

    # -- recombination through delegation -------------------------------
    out.extend(_delegation_findings(policy, registry))

    # -- taint laundering across siblings -------------------------------
    sinks = policy.data.egress_sinks & policy.tool_names
    readers = {n for n in policy.tool_names
               if (s := registry.spec(n)) and
               int(s.classification) > int(policy.data.egress_max_classification)}
    if sinks and readers and policy.spawn.max_fanout > 1:
        out.append(Finding(
            "taint_laundering", "high", "taint does not cross agents",
            f"one child can read sensitive data ({sorted(readers)}) while a "
            f"sibling holds a sink ({sorted(sinks)}). Taint is per-grant, so if "
            f"your orchestration passes one child's output into another's "
            f"input, the second is untainted and may export it. The kernel "
            f"cannot see that hand-off -- mediate inter-agent messages or give "
            f"readers and sinks to disjoint subtrees"))

    return out


def _is_empty(c: ArgConstraint) -> bool:
    return all(getattr(c, f) is None for f in ArgConstraint.__dataclass_fields__)


def _delegation_findings(policy: Policy, registry: ToolRegistry) -> list[Finding]:
    out = []
    sp = policy.spawn
    if sp.max_depth <= 0:
        return out

    delegable = (sp.allow_tools if sp.allow_tools is not None
                 else policy.tool_names) & policy.tool_names

    # worst-case concurrent agents
    worst = sum(sp.max_fanout ** d for d in range(1, sp.max_depth + 1))
    if sp.max_descendants >= worst and worst > 8:
        out.append(Finding(
            "delegation_shape", "medium", "descendant cap is not binding",
            f"depth {sp.max_depth} x fan-out {sp.max_fanout} permits {worst} "
            f"descendants, and max_descendants is {sp.max_descendants}; the cap "
            f"never engages"))

    sinks = delegable & policy.data.egress_sinks
    readers = {n for n in delegable
               if (s := registry.spec(n)) and
               int(s.classification) > int(policy.data.egress_max_classification)}
    if sinks and readers:
        out.append(Finding(
            "delegation_shape", "medium", "read and export delegable together",
            f"a single child may hold both a sensitive reader {sorted(readers)} "
            f"and a sink {sorted(sinks)}. Taint blocks the sequence today, but "
            f"the combination exists only because allow_tools permits it"))

    if "agent.spawn" in delegable and sp.child_budget_fraction > 0.5:
        out.append(Finding(
            "delegation_shape", "medium", "slow budget decay",
            f"children may spawn and keep {sp.child_budget_fraction:.0%} of the "
            f"remaining budget; authority decays slowly down the chain"))
    return out


# ======================================================================
# 2. ADVERSARIAL PAYLOAD PROBING
# ======================================================================

@dataclass(frozen=True)
class Payload:
    value: str
    why: str
    severity: str = "high"


_PAYLOADS: dict[str, tuple[Payload, ...]] = {
    "path": (
        Payload("/etc/passwd", "absolute path outside the sandbox", "critical"),
        Payload("/workspace/../etc/shadow", "parent traversal", "critical"),
        Payload("/workspace/./../../root/.ssh/id_rsa", "dot-segment traversal", "critical"),
        Payload("/workspace/%2e%2e/etc/passwd", "percent-encoded traversal", "high"),
        Payload("/workspace/....//etc/passwd", "doubled dot-segment", "high"),
        Payload("/workspace/\x00/etc/passwd", "null-byte truncation", "high"),
        Payload("/workspace/sub/../../etc/passwd", "traversal after a valid prefix", "critical"),
        Payload("/workspace/link-to-root", "path that may be a symlink", "medium"),
    ),
    "url": (
        Payload("https://evil.example.com/collect", "external host", "critical"),
        Payload("http://169.254.169.254/latest/meta-data/", "cloud metadata SSRF", "critical"),
        Payload("https://api.internal.corp.evil.com/v1/x", "suffix-confusion host", "critical"),
        Payload("https://api.internal.corp@evil.example.com/v1/x", "userinfo host spoof", "critical"),
        Payload("https://api.internal.corp/v1/../../admin/keys", "path traversal on the API", "high"),
        Payload("https://api.internal.corp/v1/x?redirect=https://evil.example.com",
                "open-redirect parameter", "medium"),
        Payload("https://API.INTERNAL.CORP/v1/x", "case-varied host", "medium"),
        Payload("file:///etc/passwd", "non-http scheme", "critical"),
    ),
    "sql": (
        Payload("SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'",
                "SELECT that writes to disk", "critical"),
        Payload("SELECT pg_read_file('/etc/passwd')",
                "SELECT that reads arbitrary files", "critical"),
        Payload("SELECT load_file('/etc/passwd')", "SELECT that reads files", "critical"),
        Payload("SELECT dblink_exec('host=evil.example.com', 'SELECT 1')",
                "SELECT that opens an outbound connection", "critical"),
        Payload("SELECT * FROM users UNION SELECT password FROM admin_secrets",
                "UNION reaching another table", "high"),
        Payload("SELECT/**/1;/**/DROP/**/TABLE/**/users",
                "comment-obfuscated mutation", "critical"),
        Payload("SeLeCt 1 FROM pg_shadow", "case-varied access to a credential table", "high"),
        Payload("SELECT * FROM users FOR UPDATE", "SELECT that takes write locks", "medium"),
    ),
    "content": (
        Payload("contact asha.rao@example.com", "plain PII", "high"),
        Payload("Y29udGFjdCBhc2hhLnJhb0BleGFtcGxlLmNvbQ==",
                "base64-encoded PII", "high"),
        Payload("asha.rao@ example.com".replace(" ", "\u200b"),
                "zero-width space inside an email", "high"),
        Payload("asha·rao@example·com", "homoglyph-substituted email", "medium"),
        Payload("email: asha [dot] rao [at] example [dot] com",
                "natural-language obfuscated PII", "medium"),
        Payload("4111-1111-1111-1111", "hyphenated card number", "high"),
        Payload("4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1", "space-separated card number", "high"),
    ),
}

_ARG_KIND = (
    ("path", ("path", "file", "filename", "dir", "dest")),
    ("url", ("url", "uri", "endpoint", "host", "webhook")),
    ("sql", ("sql", "query_sql", "statement")),
    ("content", ("content", "body", "payload", "text", "message", "data")),
)

_BENIGN: dict[str, str] = {
    "path": "/workspace/notes.md",
    "url": "https://api.internal.corp/v1/items",
    "sql": "SELECT id FROM items",
    "content": "row count 42",
    "generic": "hello",
}


def _kind_of(arg: str) -> str:
    low = arg.lower()
    for kind, needles in _ARG_KIND:
        if any(n in low for n in needles):
            return kind
    return "generic"


_CLASSES = {"A-Z": "A", "a-z": "a", "0-9": "0", "A-Za-z": "A",
            "a-zA-Z": "a", "0-9a-f": "0", "\\w": "a", "\\d": "0"}


def sample_from_pattern(pattern: str) -> str | None:
    """Tiny generator for the simple anchored patterns MCP schemas actually use
    (`[A-Z]{2}-[0-9]{4}`, `\\d{3}`, literals). Returns None if we cannot be sure,
    because a wrong guess produces a phantom finding."""
    p = pattern.strip()
    for a in ("^", "$"):
        p = p.removeprefix(a) if a == "^" else p.removesuffix(a)
    out, i = [], 0
    token = re.compile(r"(\[[^\]]+\]|\\[dwsDWS]|[A-Za-z0-9_./@:-])(\{(\d+)(,\d+)?\})?")
    while i < len(p):
        m = token.match(p, i)
        if not m:
            return None
        atom, count = m.group(1), int(m.group(3) or 1)
        if atom.startswith("["):
            inner = atom[1:-1]
            if inner.startswith("^"):
                return None
            ch = _CLASSES.get(inner) or (inner[0] if inner and inner[0].isalnum() else None)
            if ch is None:
                return None
        elif atom.startswith("\\"):
            ch = _CLASSES.get(atom)
            if ch is None:
                return None
        else:
            ch = atom
        out.append(ch * count)
        i = m.end()
    return "".join(out) or None


def _benign_args(rule: ToolRule) -> dict[str, str]:
    args: dict[str, str] = {}
    for arg in set(rule.require_args) | set(rule.args):
        kind = _kind_of(arg)
        val = _BENIGN[kind]
        c = rule.args.get(arg)
        if c is not None and c.prefix and not val.startswith(c.prefix):
            val = c.prefix + "ok"
        if c is not None and c.matches:
            sampled = sample_from_pattern(c.matches)
            if sampled is not None:
                val = sampled
        if c is not None and c.one_of:
            val = str(c.one_of[0])
        args[arg] = val
    return args


def probe_findings(policy: Policy, registry: ToolRegistry) -> list[Finding]:
    kernel = Kernel(registry, dry_run=True)
    out: list[Finding] = []

    for name, rule in sorted(policy.tools.items()):
        if name == "agent.spawn":
            continue
        base = _benign_args(rule)
        grant = Grant.root(policy, "probe")
        if not kernel.decide(grant, Call(tool=name, args=dict(base))).allowed:
            out.append(Finding(
                "probe_skipped", "info", "no benign baseline",
                "could not construct an allowed baseline call, so this tool "
                "was not probed; widen the benign fixture", tool=name))
            continue

        for arg in sorted(base):
            kind = _kind_of(arg)
            for payload in _PAYLOADS.get(kind, ()):
                args = dict(base)
                args[arg] = payload.value
                grant = Grant.root(policy, "probe")   # fresh, untainted
                if kernel.decide(grant, Call(tool=name, args=args)).allowed:
                    out.append(Finding(
                        "payload_admitted", payload.severity,
                        f"dangerous {kind} payload is allowed",
                        payload.why, tool=name, arg=arg,
                        witness=payload.value))
    return out


# ======================================================================
# 3. METAMORPHIC MUTATION OF DENY CASES
# ======================================================================

def _mutations(s: str) -> list[tuple[str, str]]:
    """(mutated, technique). Each preserves the dangerous meaning."""
    muts: list[tuple[str, str]] = [
        (s.upper(), "uppercase"),
        (s.lower(), "lowercase"),
        (s.replace("..", "%2e%2e"), "percent-encode dot segments"),
        (s.replace("/", "//"), "doubled separators"),
        (s.replace(" ", "/**/", 1) if " " in s else s, "sql comment for space"),
        (s.replace(" ", "\t"), "tab for space"),
        (s + "\n", "trailing newline"),
        (s + "\x00", "trailing null byte"),
        (s + "#", "trailing fragment"),
        (s + "   ", "trailing whitespace"),
        ("\u200b".join(s), "zero-width joiners"),
        (s.replace(".", "\u002e"), "unicode dot"),
        (s.replace("://", ":///"), "extra scheme slash"),
    ]
    seen, out = {s}, []
    for m, why in muts:
        if m not in seen:
            seen.add(m)
            out.append((m, why))
    return out


def metamorphic_findings(policy: Policy, registry: ToolRegistry,
                         steps: Iterable[Step]) -> list[Finding]:
    kernel = Kernel(registry, dry_run=True)
    out: list[Finding] = []
    for step in steps:
        if step.kind != "invoke" or step.expect != "deny":
            continue
        grant = Grant.root(policy, "mutant")
        if kernel.decide(grant, Call(tool=step.tool, args=dict(step.args))).allowed:
            continue                              # not actually denied here
        for arg, value in step.args.items():
            if not isinstance(value, str):
                continue
            for mutated, technique in _mutations(value):
                args = dict(step.args)
                args[arg] = mutated
                grant = Grant.root(policy, "mutant")
                if kernel.decide(grant, Call(tool=step.tool, args=args)).allowed:
                    out.append(Finding(
                        "mutation_bypass", "critical",
                        "a denied call is allowed after mutation",
                        f"the original payload is refused, but the same payload "
                        f"under '{technique}' passes every guard",
                        tool=step.tool, arg=arg, witness=mutated))
    return out


# ======================================================================
# Orchestration + baseline
# ======================================================================

@dataclass
class AuditReport:
    findings: list[Finding] = field(default_factory=list)
    accepted: dict[str, str] = field(default_factory=dict)

    @property
    def new(self) -> list[Finding]:
        return [f for f in self.findings if f.fingerprint not in self.accepted]

    def blocking(self, threshold: str = "high") -> list[Finding]:
        cut = SEVERITIES.index(threshold)
        return [f for f in self.new if SEVERITIES.index(f.severity) <= cut]

    def by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {s: [] for s in SEVERITIES}
        for f in self.findings:
            out[f.severity].append(f)
        return out


def load_baseline(path: str | Path) -> dict[str, str]:
    p = Path(path)
    if not p.exists():
        return {}
    raw = yaml.safe_load(p.read_text()) or {}
    return {e["fingerprint"]: e.get("reason", "") for e in raw.get("accepted", [])}


def hunt(policy: Policy, registry: ToolRegistry | None = None, *,
         suite_paths: Iterable[str | Path] = (),
         baseline: str | Path | None = None) -> AuditReport:
    registry = registry or build_fixture_registry(policy)[0]
    findings = static_findings(policy, registry)
    findings += probe_findings(policy, registry)

    steps: list[Step] = []
    for sp in suite_paths:
        for case in load_suite(sp).cases:
            steps.extend(case.steps)
    if steps:
        findings += metamorphic_findings(policy, registry, steps)

    findings = consolidate(findings)

    # de-duplicate by fingerprint, keep the first
    seen, unique = set(), []
    for f in findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITIES.index(f.severity), f.category, f.tool))

    return AuditReport(findings=unique,
                       accepted=load_baseline(baseline) if baseline else {})


def consolidate(findings: list[Finding]) -> list[Finding]:
    """Collapse the corpus dimension.

    Twelve traversal payloads across three filesystem tools is not twelve
    problems, it is three unconstrained path arguments. Reporting it as twelve
    is how a scanner teaches its reader to skim. Grouping also keeps
    fingerprints stable when the payload corpus grows, which matters because
    the baseline file is keyed on them.
    """
    grouped: dict[tuple[str, str], list[Finding]] = {}
    passthrough: list[Finding] = []
    schema_gaps = {(f.tool, f.arg) for f in findings
                   if f.category == "unconstrained_schema" and f.arg}

    for f in findings:
        if f.category == "payload_admitted":
            grouped.setdefault((f.tool, f.arg), []).append(f)
        elif f.category == "unconstrained_arg" and (f.tool, f.arg) in schema_gaps:
            continue                      # the MCP check already says this
        elif f.category == "probe_skipped":
            continue                      # an internal limit, not the user's bug
        else:
            passthrough.append(f)

    merged: list[Finding] = []
    for (tool, arg), group in grouped.items():
        group.sort(key=lambda f: SEVERITIES.index(f.severity))
        worst = group[0]
        reasons = "; ".join(dict.fromkeys(f.detail for f in group))
        extra = [f.witness for f in group[1:4] if f.witness]
        detail = f"{len(group)} dangerous payload(s) accepted: {reasons}"
        if extra:
            detail += ". Also reproduces with: " + ", ".join(repr(w) for w in extra)
        merged.append(Finding(
            "payload_admitted", worst.severity, "dangerous payloads accepted",
            detail, tool=tool, arg=arg, witness=worst.witness))

    out = passthrough + merged
    out.sort(key=lambda f: (SEVERITIES.index(f.severity), f.category, f.tool, f.arg))
    return out


def format_audit(report: AuditReport) -> str:
    lines = []
    buckets = report.by_severity()
    for sev in SEVERITIES:
        if not buckets[sev]:
            continue
        for f in buckets[sev]:
            mark = "  " if f.fingerprint not in report.accepted else "~ "
            lines.append(mark + str(f))
    counts = ", ".join(f"{len(buckets[s])} {s}" for s in SEVERITIES if buckets[s])
    lines.append("")
    lines.append(f"{len(report.findings)} findings ({counts}); "
                 f"{len(report.accepted)} accepted in baseline, "
                 f"{len(report.new)} new")
    return "\n".join(lines)

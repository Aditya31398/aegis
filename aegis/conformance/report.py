"""The deliverable.

An audit is worth paying for when the customer can act on it without a second
meeting. So every finding carries three things: what is wrong, the exact input
that demonstrates it, and what to change. Findings without a witness are
opinions, and opinions are what the customer already had.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date
from pathlib import Path

from aegis.adapters.mcp import McpServer

from .loopholes import SEVERITIES, AuditReport, Finding

_REMEDIATION: dict[str, str] = {
    "unconstrained_schema":
        "Add `enum`, `pattern` or `maxLength` to the JSON Schema, and set "
        "`additionalProperties: false`. The schema is the enforcement surface; "
        "handler-side checks run after the model has already chosen the call.",
    "omnibus_tool":
        "Split the handler into one tool per operation with an explicit schema "
        "each. A single free-form dispatcher grants the union of everything it "
        "can reach, which is almost never what was intended.",
    "tool_shadowing":
        "Namespace tool names per server, or pin the client to an explicit "
        "server-to-tool mapping so routing is not resolution-order dependent.",
    "description_injection":
        "Treat descriptions as untrusted model input. Strip Unicode format "
        "characters, reject imperative second-person text at registration, and "
        "diff descriptions on every server update.",
    "irreversible_no_brake":
        "Add a required `confirm` or `dry_run` argument, and default to the "
        "non-destructive path. Irreversible actions should need two decisions.",
    "plaintext_secret":
        "Move production credentials to the OS keychain or a secret manager. "
        "Scope each credential to exactly what the tool needs, and use separate "
        "keys per environment.",
    "unauthenticated_transport":
        "Require a bearer token on the remote transport and verify that an "
        "invalid token is rejected with 401 rather than ignored.",
    "payload_admitted":
        "Tighten the argument constraint so the witness below is refused. The "
        "generated hardened policy contains a starting pattern.",
    "unscreened_exit":
        "Declare the tool as an egress sink so PII and classification checks "
        "run before data leaves.",
    "mutation_bypass":
        "Normalise input before matching (NFKC, strip format characters) and "
        "re-test. Pattern matching on raw input loses to encoding every time.",
}

_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def render_markdown(report: AuditReport, servers: list[McpServer], *,
                    client: str = "", hardened_path: str = "") -> str:
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        buckets[f.severity].append(f)

    tool_count = sum(len(s.tools) for s in servers)
    crit = len(buckets["critical"])
    high = len(buckets["high"])

    L: list[str] = []
    L.append(f"# Agent tool-surface audit{f' — {client}' if client else ''}")
    L.append("")
    L.append(f"*{date.today().isoformat()} · {len(servers)} server(s), "
             f"{tool_count} tools examined*")
    L.append("")

    # -- summary -------------------------------------------------------
    L.append("## Summary")
    L.append("")
    if crit or high:
        L.append(f"**{crit} critical and {high} high-severity findings.** "
                 f"Each one below includes the exact input that reproduces it.")
    else:
        L.append("No critical or high-severity findings. Medium and low items "
                 "below are worth scheduling, not worth paging anyone.")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in SEVERITIES:
        if buckets[sev]:
            L.append(f"| {sev.title()} | {len(buckets[sev])} |")
    L.append("")
    L.append("Findings were produced by three methods: structural analysis of "
             "the declared schemas, adversarial payload probing against the "
             "real decision path, and meaning-preserving mutation of inputs "
             "that are supposed to be refused. Nothing in this audit executed "
             "a tool against your infrastructure.")
    L.append("")

    # -- inventory -----------------------------------------------------
    L.append("## Surface inventory")
    L.append("")
    L.append("| Server | Tools | Transport |")
    L.append("|---|---|---|")
    for s in servers:
        L.append(f"| `{s.name}` | {len(s.tools)} | {s.transport} |")
    L.append("")

    # -- findings ------------------------------------------------------
    L.append("## Findings")
    for sev in SEVERITIES:
        if not buckets[sev]:
            continue
        L.append("")
        L.append(f"### {sev.title()}")
        for f in sorted(buckets[sev], key=lambda x: (x.category, x.tool)):
            loc = f.tool + (f".{f.arg}" if f.arg else "")
            L.append("")
            L.append(f"#### `{f.fingerprint}` — {f.title}")
            L.append("")
            if loc:
                L.append(f"**Where:** `{loc}`  ")
            L.append(f"**Confidence:** {f.confidence}  ")
            L.append(f"**What:** {f.detail}")
            if f.witness:
                L.append("")
                L.append("**Reproduces with:**")
                L.append("")
                L.append("```")
                L.append(f.witness)
                L.append("```")
            fix = _REMEDIATION.get(f.category)
            if fix:
                L.append("")
                L.append(f"**Fix:** {fix}")

    # -- next steps ----------------------------------------------------
    L.append("")
    L.append("## What to do first")
    L.append("")
    ordered = sorted(report.findings,
                     key=lambda f: (_SEV_ORDER[f.severity], f.category))[:5]
    if ordered:
        for i, f in enumerate(ordered, 1):
            loc = f.tool + (f".{f.arg}" if f.arg else "")
            L.append(f"{i}. **{f.title}** on `{loc}` ({f.severity})")
    else:
        L.append("Nothing urgent. Re-run this audit on every schema change.")
    L.append("")
    if hardened_path:
        L.append(f"A hardened policy covering these tools is included as "
                 f"`{hardened_path}`. Placeholders in it are marked in capitals "
                 f"and need a decision from someone who knows the deployment; "
                 f"it is a starting point, not a drop-in.")
        L.append("")
    L.append("## Keeping it fixed")
    L.append("")
    L.append("Findings carry stable fingerprints. Accept the ones you decide "
             "not to close in a baseline file with a written reason, then run "
             "this audit in CI. The known-hole set can then shrink silently but "
             "never grow silently, which is the only property that survives a "
             "team changing the schemas six months from now.")
    L.append("")
    return "\n".join(L)


def write_report(report: AuditReport, servers: list[McpServer], path: str | Path,
                 **kw) -> Path:
    path = Path(path)
    path.write_text(render_markdown(report, servers, **kw), encoding="utf-8")
    return path

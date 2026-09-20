"""Machine-readable output: JSON for pipelines, SARIF for security dashboards.

SARIF 2.1.0 is what GitHub code scanning, Azure DevOps, Defender for Cloud and
most enterprise vulnerability platforms ingest. Two mappings carry the weight:

* `partialFingerprints` gets our stable finding fingerprint, so a dashboard
  dedupes the same hole across runs instead of opening a new alert per build.
* baselined findings are emitted with an external `suppression` carrying the
  written reason, so an accepted risk stays visible and auditable rather than
  silently disappearing.

The JSON schema is versioned (`schema`), and adding fields is not a breaking
change; removing or renaming one is.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .. import __version__
from .loopholes import SEVERITIES, AuditReport, Finding

JSON_SCHEMA = "aegis.audit/v1"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/Aditya31398/aegis"

_SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0",
                      "low": "3.0", "info": "0.0"}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}


def to_json(report: AuditReport, *, source: str | Path | None = None,
            threshold: str = "high", corpus_version: int | None = None
            ) -> dict[str, Any]:
    blocking = {f.fingerprint for f in report.blocking(threshold)}
    counts = {s: 0 for s in SEVERITIES}
    for f in report.findings:
        counts[f.severity] += 1
    return {
        "schema": JSON_SCHEMA,
        "tool": {"name": "aegis", "version": __version__,
                 **({"corpus_version": corpus_version} if corpus_version else {})},
        "source": str(source) if source else None,
        "fail_on": threshold,
        "passed": not blocking,
        "summary": {"total": len(report.findings), "by_severity": counts,
                    "accepted": sum(1 for f in report.findings
                                    if f.fingerprint in report.accepted),
                    "blocking": len(blocking)},
        "findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "tool": f.tool,
                "arg": f.arg,
                "witness": f.witness,
                "accepted": f.fingerprint in report.accepted,
                "accepted_reason": report.accepted.get(f.fingerprint),
                "blocking": f.fingerprint in blocking,
            }
            for f in report.findings
        ],
    }


def to_sarif(report: AuditReport, *, source: str | Path | None = None
             ) -> dict[str, Any]:
    uri = _uri(source)
    text = _read(source)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in report.findings:
        rule = rules.setdefault(f.category, _rule(f))
        # A rule's severity is the worst severity it was seen at.
        if float(_SECURITY_SEVERITY[f.severity]) > float(
                rule["properties"]["security-severity"]):
            rule["properties"]["security-severity"] = _SECURITY_SEVERITY[f.severity]
            rule["defaultConfiguration"]["level"] = _LEVEL[f.severity]
        result: dict[str, Any] = {
            "ruleId": f.category,
            "level": _LEVEL[f.severity],
            "message": {"text": _message(f)},
            "partialFingerprints": {"aegisFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity, "tool": f.tool, "arg": f.arg,
                           **({"witness": f.witness} if f.witness else {})},
        }
        if uri:
            result["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": _line_of(text, f)},
            }}]
        if f.fingerprint in report.accepted:
            result["suppressions"] = [{
                "kind": "external", "status": "accepted",
                "justification": report.accepted[f.fingerprint] or "baselined"}]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "aegis",
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": sorted(rules.values(), key=lambda r: r["id"]),
            }},
            "results": results,
        }],
    }


def write(report: AuditReport, fmt: str, path: str | Path, *,
          source: str | Path | None = None, threshold: str = "high",
          corpus_version: int | None = None) -> Path:
    doc = (to_sarif(report, source=source) if fmt == "sarif"
           else to_json(report, source=source, threshold=threshold,
                        corpus_version=corpus_version))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path


def dumps(report: AuditReport, fmt: str, *, source=None, threshold="high",
          corpus_version: int | None = None) -> str:
    doc = (to_sarif(report, source=source) if fmt == "sarif"
           else to_json(report, source=source, threshold=threshold,
                        corpus_version=corpus_version))
    return json.dumps(doc, indent=2)


# ----------------------------------------------------------------------

def _rule(f: Finding) -> dict[str, Any]:
    return {
        "id": f.category,
        "name": "".join(w.capitalize() for w in f.category.split("_")),
        "shortDescription": {"text": f.category.replace("_", " ")},
        "helpUri": f"{INFO_URI}#readme",
        "defaultConfiguration": {"level": _LEVEL[f.severity]},
        "properties": {"tags": ["security", "ai-agents"],
                       "security-severity": _SECURITY_SEVERITY[f.severity]},
    }


def _message(f: Finding) -> str:
    where = f.tool + (f".{f.arg}" if f.arg else "")
    msg = f"{f.title}: {f.detail}" if f.detail else f.title
    if where:
        msg = f"[{where}] {msg}"
    if f.witness:
        msg += f" (witness: {f.witness})"
    return msg


def _uri(source: str | Path | None) -> str | None:
    if not source:
        return None
    p = Path(source)
    try:
        # Code scanning resolves locations relative to the repo root; CI runs
        # from there, so relative-to-cwd is the right default.
        rel = os.path.relpath(p.resolve(), Path.cwd())
        if not rel.startswith(".."):
            return Path(rel).as_posix()
    except ValueError:                        # different drive on Windows
        pass
    return p.resolve().as_uri()


def _read(source: str | Path | None) -> str:
    try:
        return Path(source).read_text(encoding="utf-8") if source else ""
    except OSError:
        return ""


def _line_of(text: str, f: Finding) -> int:
    """Best-effort line of the offending tool in the source file. Falls back
    to line 1, which SARIF consumers accept, rather than guessing wrong."""
    if not text or not f.tool:
        return 1
    candidates = [f.tool]
    if "." in f.tool:
        candidates.append(f.tool.split(".", 1)[1])      # server.tool -> tool
    lines = text.splitlines()
    for needle in candidates:
        for quoted in (f'"{needle}"', f"name: {needle}", needle):
            for i, line in enumerate(lines, 1):
                if quoted in line:
                    return i
    return 1

"""Data-access and egress control.

Two mechanisms:
  * Classification ceiling -- a tool declares the sensitivity of what it
    returns; reading above the grant's ceiling is denied outright.
  * Taint + egress -- once an agent reads CONFIDENTIAL data it is tainted, and
    any call to a declared egress sink is checked against the egress ceiling
    and scanned for PII patterns. Fail-closed on both.

The scanner is deliberately conservative: it is a backstop, not the primary
control. The primary control is that the agent never holds the raw callable.
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Any

from ..decision import Classification, Verdict
from ..grant import Grant
from .base import Call

# --------------------------------------------------------------------------
# Normalisation -- added after the loophole hunter found zero-width and
# homoglyph bypasses of every pattern below.
# --------------------------------------------------------------------------

_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u2061\u2062\u2063"), None)

_CONFUSABLES = {
    "·": ".", "‧": ".", "∙": ".", "•": ".", "․": ".", "⋅": ".", "。": ".",
    "＠": "@", "﹫": "@", "＠": "@", "(at)": "@", "[at]": "@",
    "－": "-", "‐": "-", "‑": "-", "–": "-", "—": "-",
}


def normalize(text: str) -> str:
    """Canonical form used for every PII check.

    NFKC folds fullwidth and compatibility forms; invisible formatting
    characters are dropped; a small confusables table handles the separators
    people actually use to slip an address past a regex.
    """
    t = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    t = "".join(c for c in t if unicodedata.category(c) != "Cf")
    for bad, good in _CONFUSABLES.items():
        t = t.replace(bad, good)
    return t


_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decoded_views(text: str) -> list[str]:
    """Base64 blobs decoded so encoded PII is scanned too."""
    views: list[str] = []
    for m in _B64.finditer(text):
        blob = m.group()
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable():
            views.append(decoded)
    return views

# --------------------------------------------------------------------------
# PII detectors
# --------------------------------------------------------------------------


def _luhn(digits: str) -> bool:
    ds = [int(c) for c in digits][::-1]
    total = 0
    for i, d in enumerate(ds):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "phone_in": re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{9}\b"),
    "phone_e164": re.compile(r"\+\d{1,3}[\s-]?\d{6,12}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "aadhaar": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "api_key": re.compile(r"\b(?:sk|pk|ghp|xox[baprs])[-_][A-Za-z0-9]{16,}\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}

_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def scan_pii(text: str, kinds: frozenset[str]) -> list[tuple[str, str]]:
    """Return (kind, matched_snippet) for every requested PII kind found.

    Scans the normalised text plus any base64-decoded views of it, so
    encoding and invisible-character tricks do not defeat the patterns.
    """
    hits: list[tuple[str, str]] = []
    canonical = normalize(text)
    for view in [canonical, *_decoded_views(canonical)]:
        hits.extend(_scan_one(view, kinds))
    return hits


def _scan_one(text: str, kinds: frozenset[str]) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for kind in kinds:
        if kind == "credit_card":
            for m in _CARD.finditer(text):
                digits = re.sub(r"[ -]", "", m.group())
                if 13 <= len(digits) <= 19 and _luhn(digits):
                    hits.append((kind, _mask(m.group())))
            continue
        pat = _PATTERNS.get(kind)
        if pat is None:
            continue
        for m in pat.finditer(text):
            hits.append((kind, _mask(m.group())))
    return hits


def _mask(s: str) -> str:
    return s[:2] + "*" * max(0, len(s) - 4) + s[-2:] if len(s) > 4 else "****"


def redact(text: str, kinds: frozenset[str]) -> str:
    out = text
    for kind, _ in scan_pii(text, kinds):
        pass
    for kind in kinds:
        if kind == "credit_card":
            out = _CARD.sub(lambda m: "[REDACTED:credit_card]"
                            if _luhn(re.sub(r"[ -]", "", m.group())) else m.group(), out)
        elif kind in _PATTERNS:
            out = _PATTERNS[kind].sub(f"[REDACTED:{kind}]", out)
    return out


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v) for v in value)
    return str(value)


# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------


class DataGuard:
    """Pre-call: block egress of tainted or PII-bearing payloads."""

    name = "data"

    def check(self, grant: Grant, call: Call) -> Verdict:
        dp = grant.policy.data
        if call.tool not in dp.egress_sinks:
            return Verdict.allow("data.not_egress", self.name)

        if grant.taint > int(dp.egress_max_classification):
            return Verdict.deny(
                "data.taint_egress_blocked",
                f"agent holds {Classification(grant.taint).name} data; egress "
                f"ceiling is {dp.egress_max_classification.name}",
                self.name, taint=grant.taint)

        payload = _flatten(call.args)
        hits = scan_pii(payload, dp.block_pii)
        if hits:
            if dp.redact_instead_of_deny:
                call.args = _redact_args(call.args, dp.block_pii)
                return Verdict.allow("data.redacted", self.name,
                                     redacted=[k for k, _ in hits])
            return Verdict.deny(
                "data.pii_egress_blocked",
                f"payload contains {sorted({k for k, _ in hits})}",
                self.name, kinds=sorted({k for k, _ in hits}),
                samples=[s for _, s in hits][:3])

        return Verdict.allow("data.clean", self.name)


def _redact_args(args: dict[str, Any], kinds: frozenset[str]) -> dict[str, Any]:
    return {k: (redact(v, kinds) if isinstance(v, str) else v) for k, v in args.items()}


class ClassificationPostGuard:
    """Post-call: enforce the read ceiling and raise the agent's taint."""

    name = "classification"

    def inspect(self, grant: Grant, call: Call, result: Any) -> Verdict:
        level = Classification.parse(
            call.meta.get("classification", Classification.PUBLIC))
        ceiling = grant.policy.data.max_classification
        if int(level) > int(ceiling):
            return Verdict.deny(
                "data.classification_exceeded",
                f"'{call.tool}' returned {level.name} data but grant ceiling "
                f"is {ceiling.name}",
                self.name, level=level.name)
        grant.taint = max(grant.taint, int(level))
        return Verdict.allow("data.within_ceiling", self.name, taint=grant.taint)

"""Append-only, hash-chained audit log.

Every kernel decision -- allow and deny alike -- is recorded. The chain means
a record cannot be edited or dropped after the fact without breaking
`verify()`. Conformance runs assert on this log, not on side effects, so a
test can prove "nothing happened" rather than just "nothing was observed".
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: float
    agent: str
    grant_id: str
    depth: int
    tool: str
    args_digest: str
    allowed: bool
    rule: str
    reason: str
    guard: str
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    hash: str = ""


def _digest(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()
        self._path = Path(path) if path else None

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self):
        return iter(self._records)

    @property
    def records(self) -> list[AuditRecord]:
        return list(self._records)

    def append(self, *, agent: str, grant_id: str, depth: int, tool: str,
               args: dict, verdict) -> AuditRecord:
        with self._lock:
            prev = self._records[-1].hash if self._records else GENESIS
            body = {
                "seq": len(self._records), "agent": agent, "grant_id": grant_id,
                "depth": depth, "tool": tool, "args_digest": _digest(args),
                "allowed": verdict.allowed, "rule": verdict.rule,
                "guard": verdict.guard, "details": verdict.details,
                "prev_hash": prev,
            }
            rec = AuditRecord(
                seq=body["seq"], ts=time.time(), agent=agent, grant_id=grant_id,
                depth=depth, tool=tool, args_digest=body["args_digest"],
                allowed=verdict.allowed, rule=verdict.rule, reason=verdict.reason,
                guard=verdict.guard, details=verdict.details, prev_hash=prev,
                hash=_digest(body),
            )
            self._records.append(rec)
            if self._path:
                with self._path.open("a") as fh:
                    fh.write(json.dumps(asdict(rec), default=str) + "\n")
            return rec

    def verify(self) -> bool:
        prev = GENESIS
        for rec in self._records:
            body = {
                "seq": rec.seq, "agent": rec.agent, "grant_id": rec.grant_id,
                "depth": rec.depth, "tool": rec.tool,
                "args_digest": rec.args_digest, "allowed": rec.allowed,
                "rule": rec.rule, "guard": rec.guard, "details": rec.details,
                "prev_hash": prev,
            }
            if rec.prev_hash != prev or rec.hash != _digest(body):
                return False
            prev = rec.hash
        return True

    # -- query helpers used by the conformance runner ---------------------
    def denials(self) -> list[AuditRecord]:
        return [r for r in self._records if not r.allowed]

    def rules(self) -> list[str]:
        return [r.rule for r in self._records]

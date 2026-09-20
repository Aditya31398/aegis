"""The payload corpus is data, not code.

It is the part of the project most likely to change between releases and the
part a customer most wants to refresh on its own cadence. Two properties make
that safe: a corpus can be swapped in without touching the package, and
swapping it can never invalidate an existing baseline.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from aegis.conformance import loopholes
from aegis.conformance.cli import main as cli
from aegis.conformance.loopholes import (CORPUS_SCHEMA, SEVERITIES, CorpusError,
                                         corpus_version, hunt,
                                         load_payload_corpus)
from aegis.policy import load_policy

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "policies" / "base.yaml"
PACKAGED = ROOT / "aegis" / "corpus" / "payloads.yaml"


def _corpus_doc():
    return yaml.safe_load(PACKAGED.read_text(encoding="utf-8"))


# ----------------------------------------------------------------------
# The packaged corpus
# ----------------------------------------------------------------------
def test_packaged_corpus_loads_and_is_well_formed():
    corpus = load_payload_corpus()
    assert set(corpus) >= {"path", "url", "sql", "content"}
    for kind, payloads in corpus.items():
        assert payloads, kind
        for p in payloads:
            assert p.value and p.why and p.severity in SEVERITIES
    assert corpus_version() >= 1
    assert _corpus_doc()["schema"] == CORPUS_SCHEMA


def test_every_corpus_kind_is_reachable_from_an_argument_name():
    """A payload kind no argument maps to is a probe that never runs, which
    looks exactly like a clean audit."""
    reachable = {kind for kind, _ in loopholes._ARG_KIND}
    assert set(load_payload_corpus()) <= reachable


def test_hostile_bytes_survive_the_yaml_round_trip():
    """Null bytes and zero-width characters are the point of those payloads;
    a corpus format that mangles them silently weakens every probe."""
    corpus = load_payload_corpus()
    values = [p.value for ps in corpus.values() for p in ps]
    assert any("\x00" in v for v in values)
    assert any("\u200b" in v for v in values)


# ----------------------------------------------------------------------
# The property that lets the corpus be updated at all
# ----------------------------------------------------------------------
def _write_corpus(path: Path, payloads: dict, version: int = 99) -> Path:
    path.write_text(yaml.safe_dump(
        {"schema": CORPUS_SCHEMA, "version": version, "payloads": payloads},
        sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def test_adding_payloads_never_changes_existing_fingerprints(tmp_path):
    """The regression this whole design exists for: a corpus refresh may
    reveal a new hole, but must never invalidate a customer's baseline."""
    policy = load_policy(BASE)
    before = {f.fingerprint: f.category for f in hunt(policy).findings}

    doc = _corpus_doc()["payloads"]
    # A new payload at the *front* of every kind: the witness a consolidated
    # finding shows is drawn from corpus order, so this is the worst case.
    for kind in doc:
        doc[kind].insert(0, {"value": f"BRAND-NEW-{kind}-PAYLOAD",
                             "why": "added by a corpus refresh",
                             "severity": "critical"})
    path = _write_corpus(tmp_path / "newer.yaml", doc)

    after = {f.fingerprint: f.category for f in hunt(policy, corpus=path).findings}
    assert set(before) <= set(after), "a corpus refresh invalidated a fingerprint"


def test_a_new_payload_can_still_reveal_a_new_finding(tmp_path):
    """...but the corpus must not be inert: a payload that gets through has
    to surface, otherwise nothing is gained by updating it."""
    policy = load_policy(BASE)
    doc = {"path": [{"value": "/workspace/notes.md", "why": "benign control",
                     "severity": "info"}],
           "sql": [{"value": "SELECT secrets FROM vault", "why": "new technique",
                    "severity": "critical"}]}
    findings = hunt(policy, corpus=_write_corpus(tmp_path / "c.yaml", doc)).findings
    admitted = [f for f in findings if f.category == "payload_admitted"]
    assert admitted, "a payload the policy admits produced no finding"
    assert any("new technique" in f.detail for f in admitted)


def test_corpus_can_be_supplied_by_environment(tmp_path, monkeypatch):
    path = _write_corpus(tmp_path / "env.yaml", {
        "sql": [{"value": "SELECT 1", "why": "env corpus", "severity": "low"}]})
    monkeypatch.setenv("AEGIS_CORPUS", str(path))
    assert set(load_payload_corpus()) == {"sql"}
    assert corpus_version() == 99


# ----------------------------------------------------------------------
# A corpus that cannot be trusted is refused, never silently skipped
# ----------------------------------------------------------------------
@pytest.mark.parametrize("doc,fragment", [
    ({"version": 1, "payloads": {"path": []}}, "schema"),
    ({"schema": "aegis.corpus/v9", "payloads": {"path": []}}, "schema"),
    ({"schema": CORPUS_SCHEMA, "payloads": {}}, "no payloads"),
    ({"schema": CORPUS_SCHEMA, "payloads": {"path": []}}, "non-empty"),
    ({"schema": CORPUS_SCHEMA, "payloads": {"path": [{"why": "no value"}]}}, "value"),
    ({"schema": CORPUS_SCHEMA,
      "payloads": {"path": [{"value": "x", "why": "y", "severity": "urgent"}]}},
     "severity"),
    ([], "mapping"),
])
def test_untrustworthy_corpus_is_refused(tmp_path, doc, fragment):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(CorpusError, match=fragment):
        load_payload_corpus(path)


def test_bad_corpus_is_a_usage_error_not_a_clean_audit(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: wrong\npayloads: {}\n", encoding="utf-8")
    code = cli(["audit", "--policy", str(BASE), "--corpus", str(bad)])
    assert code == 2                       # not 0 (pass) and not 1 (findings)
    assert "error:" in capsys.readouterr().err


def test_json_output_records_the_corpus_version(tmp_path, capsys):
    path = _write_corpus(tmp_path / "v.yaml", {
        "sql": [{"value": "SELECT 1", "why": "x", "severity": "low"}]}, version=42)
    cli(["audit", "--policy", str(BASE), "--corpus", str(path), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"]["corpus_version"] == 42

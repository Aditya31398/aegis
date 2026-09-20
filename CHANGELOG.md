# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Public contracts, where a change is
breaking: rule ids, CLI exit codes, the `aegis.audit/v1` JSON schema, finding
fingerprints, and the `aegis` Python API exported from `aegis/__init__.py`.

## [Unreleased]

### Added
- Effect inference reads the JSON Schema shape (path+content, url+body,
  command, confirmation flags) and MCP annotations before falling back to tool
  names; `infer_effects_detailed` returns the deciding signals.
- New MCP check `annotation_contradicts_surface`: annotations may only widen
  the inferred effects, and a `readOnlyHint` on a surface that mutates is a
  high finding naming both signals. The sample manifest now carries such a
  tool, so a run shows it (32 findings, was 26).

## [0.3.0] - 2026-09-20

First release published to PyPI. 0.1.0 and 0.2.0 were tagged but never uploaded,
so `pip install aegis-guard` works from this version on.

### Added
- **Observability hooks** (`aegis.observe`). `register_context_provider(fn)` stamps
  correlation ids (run id, trace id, workflow, node) into every audit record under
  `details.ctx`; `enable_opentelemetry()` does it for the active OTel span.
  `AuditLog.subscribe(fn)` streams each record after it is chained. A provider or
  subscriber that raises is contained with a warning and can never change a verdict.
  Records are unchanged when no provider is registered.
- **Model-spend gating.** `Kernel.reserve_spend(grant, usd=, tokens=)` holds an
  estimate against the grant's ledger and every ancestor's before a model call;
  `Kernel.settle_spend(reservation, usd=, tokens=)` books the actual cost. An
  exhausted budget or revoked grant refuses the reservation, so the call is never
  made. New allow rules `budget.reserved` and `budget.settled`; denials reuse the
  existing `budget.*` and `grant.revoked` rule ids. `BudgetLedger.record()` books
  spend that already happened (it cannot be refused, so overruns are never hidden).
- `dump_policy(policy)` (round-trips through `parse_policy`) and
  `policy_digest(policy)`, a stable content fingerprint.

### Fixed
- `Kernel(audit=AuditLog(path=...))` silently discarded the caller's log: an empty
  `AuditLog` is falsy (it defines `__len__`), so `audit or AuditLog()` replaced it
  and the audit file was never written. Found by the AgentDynamics integration tests.

## [0.2.0] - 2026-09-19

### Added
- **Installable package.** Provides the `aegis` command and `python -m aegis`.
  Typed (`py.typed`). (Not uploaded to PyPI; see 0.3.0.)
- `aegis init [--ci]` scaffolds a policy, adversarial scenarios, a loophole
  baseline and a GitHub workflow that pass every check out of the box.
- `--format json|sarif` and `--output` on `audit` and `mcp`. SARIF 2.1.0 with
  stable `partialFingerprints`, security-severity scores, source line
  locations, and baselined findings emitted as suppressions with their reason.
  `mcp` always writes `audit.json` and `audit.sarif`.
- Documented exit codes: `0` pass, `1` findings, `2` bad input, `3` internal error.
- **Async kernel:** `Kernel.ainvoke`, `Kernel.aspawn`, `Agent.atools`,
  `Agent.aspawn`. New rule `kernel.async_tool_requires_ainvoke`.
- **Concurrent fuzzing:** `aegis fuzz --async`, and a new invariant
  `every_effect_was_charged`.
- **Live MCP ingest:** `aegis mcp --server URL` (Streamable HTTP, JSON or SSE)
  and `--server-cmd CMD` (stdio), `--header`, `--bearer-env`. The client can
  only send `initialize` and `tools/list`. Anonymous listing is reported as a
  critical finding with a witness.
- GitHub Action: `server`, `bearer-token`, `upload-sarif`, working
  `comment-on-pr`, `artifact-name`, and `sarif`/`json`/`blocking` outputs. The action installs
  the exact ref it is pinned to.
- Container image `ghcr.io/aditya31398/aegis` (non-root, multi-arch, SBOM).
- Release pipeline: PyPI trusted publishing, signed build provenance for the
  wheel, sdist and image.

### Changed
- **Breaking:** the `conformance` package is now `aegis.conformance`; the
  wheel installs a single top-level `aegis` package.
  `python -m conformance.cli X` becomes `aegis X`.
- **Breaking:** `constitution.yaml` moved into the package
  (`aegis/constitution.yaml`).
- A malformed policy file raises `PolicyError` (exit `2`) instead of leaking
  `TypeError`/`AttributeError` (which exited `1`, indistinguishable from
  findings). A YAML list or scalar is rejected rather than read as empty.
- The invariant fuzzer's workload now includes well-formed calls, so budgets
  are actually exhausted; previously budget invariants passed vacuously.

### Fixed
- Installed builds crashed in `build_kernel()` because the constitution was
  not shipped in the wheel.
- File I/O is UTF-8 on every platform (Windows defaulted to cp1252).

## [0.1.0] - 2026-09-19

Initial release: capability kernel, policy language, constitution,
conformance scenarios, invariant fuzzing, privilege-drift detection, loophole
hunter, and the MCP manifest auditor.

[Unreleased]: https://github.com/Aditya31398/aegis/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Aditya31398/aegis/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Aditya31398/aegis/releases/tag/v0.1.0
